#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, Response

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"
DB_PATH = DATA_DIR / "stage297.db"

DEFAULT_STAGE289_VERIFY_URL = "http://127.0.0.1:2890/api/verify"
STAGE289_VERIFY_URL = os.environ.get("STAGE289_VERIFY_URL", DEFAULT_STAGE289_VERIFY_URL)

app = Flask(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    schema = """
    CREATE TABLE IF NOT EXISTS verification_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        input_url TEXT NOT NULL,
        manifest_text TEXT NOT NULL,
        manifest_sha256 TEXT NOT NULL,
        decision TEXT NOT NULL,
        trust_score REAL NOT NULL,
        fail_closed INTEGER NOT NULL,
        reasons_json TEXT NOT NULL,
        result_json TEXT NOT NULL,
        upstream_source TEXT NOT NULL,
        upstream_status TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_verification_results_created_at
    ON verification_results(created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_verification_results_decision
    ON verification_results(decision);

    CREATE INDEX IF NOT EXISTS idx_verification_results_input_url
    ON verification_results(input_url);

    CREATE INDEX IF NOT EXISTS idx_verification_results_trust_score
    ON verification_results(trust_score);

    CREATE INDEX IF NOT EXISTS idx_verification_results_upstream_status
    ON verification_results(upstream_status);
    """
    conn = get_db()
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()


def normalize_bool(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    return default


def normalize_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_reason_item(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return {
            "item": str(item.get("item", "unknown")),
            "ok": bool(item.get("ok", False)),
            "message": str(item.get("message", "")),
        }
    return {"item": "unknown", "ok": False, "message": str(item)}


def normalize_stage289_result(payload: dict[str, Any], manifest_text: str) -> dict[str, Any]:
    manifest_sha256 = str(payload.get("manifest_sha256", "")).strip() or sha256_text(manifest_text)

    reasons_raw = payload.get("reasons", [])
    if not isinstance(reasons_raw, list):
        reasons_raw = []

    decision = str(payload.get("decision", "reject")).strip().lower()
    if decision not in {"accept", "pending", "reject"}:
        decision = "reject"

    trust_score = max(0.0, min(1.0, round(normalize_float(payload.get("trust_score", 0.0)), 3)))

    return {
        "decision": decision,
        "trust_score": trust_score,
        "fail_closed": normalize_bool(payload.get("fail_closed", True), True),
        "reasons": [normalize_reason_item(item) for item in reasons_raw],
        "manifest_sha256": manifest_sha256,
        "verified_at": str(payload.get("verified_at", "")).strip() or utc_now_iso(),
        "upstream_source": "stage289",
        "upstream_status": "ok",
    }


def call_stage289_verify(input_url: str, manifest_text: str) -> dict[str, Any]:
    payload = {"url": input_url, "manifest": manifest_text}
    request_body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        STAGE289_VERIFY_URL,
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            status_code = resp.getcode()
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "error_type": "http_error",
            "status_code": exc.code,
            "message": f"Stage289 returned HTTP {exc.code}",
            "body": exc.read().decode("utf-8", errors="replace"),
        }
    except urllib.error.URLError as exc:
        return {
            "ok": False,
            "error_type": "url_error",
            "status_code": None,
            "message": f"Stage289 connection failed: {exc.reason}",
            "body": "",
        }
    except Exception as exc:
        return {
            "ok": False,
            "error_type": "unexpected_error",
            "status_code": None,
            "message": f"Stage289 call failed: {exc}",
            "body": "",
        }

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "error_type": "invalid_json",
            "status_code": status_code,
            "message": "Stage289 response was not valid JSON.",
            "body": raw,
        }

    result_candidate = parsed.get("result", parsed)
    if not isinstance(result_candidate, dict):
        return {
            "ok": False,
            "error_type": "invalid_shape",
            "status_code": status_code,
            "message": "Stage289 response JSON shape was invalid.",
            "body": raw,
        }

    return {
        "ok": True,
        "status_code": status_code,
        "result": normalize_stage289_result(result_candidate, manifest_text),
        "raw_response": parsed,
    }


def build_fail_closed_error_result(manifest_text: str, message: str, body: str = "") -> dict[str, Any]:
    reasons = [{"item": "stage289_connection", "ok": False, "message": message}]
    if body.strip():
        reasons.append({"item": "stage289_response_body", "ok": False, "message": body[:500]})

    return {
        "decision": "reject",
        "trust_score": 0.0,
        "fail_closed": True,
        "reasons": reasons,
        "manifest_sha256": sha256_text(manifest_text.strip()),
        "verified_at": utc_now_iso(),
        "upstream_source": "stage289",
        "upstream_status": "error",
    }


def save_result(input_url: str, manifest_text: str, result: dict[str, Any]) -> int:
    conn = get_db()
    try:
        cur = conn.execute(
            """
            INSERT INTO verification_results (
                created_at, input_url, manifest_text, manifest_sha256,
                decision, trust_score, fail_closed, reasons_json, result_json,
                upstream_source, upstream_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["verified_at"],
                input_url,
                manifest_text,
                result["manifest_sha256"],
                result["decision"],
                float(result["trust_score"]),
                1 if result["fail_closed"] else 0,
                json.dumps(result["reasons"], ensure_ascii=False, indent=2),
                json.dumps(result, ensure_ascii=False, indent=2),
                result.get("upstream_source", "unknown"),
                result.get("upstream_status", "unknown"),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def parse_filters(args) -> tuple[str, str, float | None, int]:
    limit_raw = args.get("limit", "20")
    decision = args.get("decision", "").strip().lower()
    url_query = args.get("url_query", "").strip()
    min_score_raw = args.get("min_score", "").strip()

    try:
        limit = max(1, min(1000, int(limit_raw)))
    except ValueError:
        limit = 20

    if decision not in {"accept", "pending", "reject"}:
        decision = ""

    min_score = None
    if min_score_raw:
        try:
            min_score = max(0.0, min(1.0, float(min_score_raw)))
        except ValueError:
            min_score = None

    return decision, url_query, min_score, limit


def query_results(decision: str, url_query: str, min_score: float | None, limit: int) -> list[dict[str, Any]]:
    where = []
    params: list[Any] = []

    if decision:
        where.append("decision = ?")
        params.append(decision)
    if url_query:
        where.append("input_url LIKE ?")
        params.append(f"%{url_query}%")
    if min_score is not None:
        where.append("trust_score >= ?")
        params.append(min_score)

    where_sql = "WHERE " + " AND ".join(where) if where else ""

    sql = f"""
        SELECT id, created_at, input_url, manifest_sha256, decision, trust_score,
               fail_closed, upstream_source, upstream_status
        FROM verification_results
        {where_sql}
        ORDER BY id DESC
        LIMIT ?
    """
    params.append(limit)

    conn = get_db()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    return [
        {
            "id": row["id"],
            "created_at": row["created_at"],
            "input_url": row["input_url"],
            "manifest_sha256": row["manifest_sha256"],
            "decision": row["decision"],
            "trust_score": row["trust_score"],
            "fail_closed": bool(row["fail_closed"]),
            "upstream_source": row["upstream_source"],
            "upstream_status": row["upstream_status"],
        }
        for row in rows
    ]


def get_result_row(result_id: int) -> dict[str, Any] | None:
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM verification_results WHERE id = ?", (result_id,)).fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "input_url": row["input_url"],
        "manifest_text": row["manifest_text"],
        "manifest_sha256": row["manifest_sha256"],
        "decision": row["decision"],
        "trust_score": row["trust_score"],
        "fail_closed": bool(row["fail_closed"]),
        "upstream_source": row["upstream_source"],
        "upstream_status": row["upstream_status"],
        "reasons": json.loads(row["reasons_json"]),
        "result": json.loads(row["result_json"]),
    }


def query_dashboard_summary() -> dict[str, Any]:
    conn = get_db()
    try:
        total = conn.execute("SELECT COUNT(*) AS c FROM verification_results").fetchone()["c"]
        by_decision_rows = conn.execute(
            "SELECT decision, COUNT(*) AS c FROM verification_results GROUP BY decision"
        ).fetchall()
        by_upstream_rows = conn.execute(
            "SELECT upstream_status, COUNT(*) AS c FROM verification_results GROUP BY upstream_status"
        ).fetchall()
        trust_rows = conn.execute("SELECT trust_score FROM verification_results").fetchall()
    finally:
        conn.close()

    by_decision = {"accept": 0, "pending": 0, "reject": 0}
    for row in by_decision_rows:
        if row["decision"] in by_decision:
            by_decision[row["decision"]] = row["c"]

    by_upstream = {"ok": 0, "error": 0, "unknown": 0}
    for row in by_upstream_rows:
        if row["upstream_status"] in by_upstream:
            by_upstream[row["upstream_status"]] = row["c"]

    scores = [float(row["trust_score"]) for row in trust_rows]

    def pct(value: int) -> float:
        return round((value / total) * 100.0, 1) if total else 0.0

    distribution = {"0.0-0.2": 0, "0.2-0.4": 0, "0.4-0.6": 0, "0.6-0.8": 0, "0.8-1.0": 0}
    for score in scores:
        if score < 0.2:
            distribution["0.0-0.2"] += 1
        elif score < 0.4:
            distribution["0.2-0.4"] += 1
        elif score < 0.6:
            distribution["0.4-0.6"] += 1
        elif score < 0.8:
            distribution["0.6-0.8"] += 1
        else:
            distribution["0.8-1.0"] += 1

    return {
        "total_results": total,
        "decision_counts": by_decision,
        "decision_rates": {
            "accept_rate": pct(by_decision["accept"]),
            "pending_rate": pct(by_decision["pending"]),
            "reject_rate": pct(by_decision["reject"]),
        },
        "upstream_counts": by_upstream,
        "upstream_rates": {
            "upstream_ok_rate": pct(by_upstream["ok"]),
            "upstream_error_rate": pct(by_upstream["error"]),
            "upstream_unknown_rate": pct(by_upstream["unknown"]),
        },
        "trust_score": {
            "average": round(sum(scores) / len(scores), 3) if scores else 0.0,
            "distribution": distribution,
        },
        "generated_at": utc_now_iso(),
    }


def build_report_package(result_id: int) -> dict[str, Any] | None:
    item = get_result_row(result_id)
    if item is None:
        return None

    report = {
        "report_type": "verification_report_package",
        "stage": 297,
        "generated_at": utc_now_iso(),
        "subject": {
            "result_id": item["id"],
            "input_url": item["input_url"],
            "created_at": item["created_at"],
        },
        "decision": {
            "decision": item["decision"],
            "trust_score": item["trust_score"],
            "fail_closed": item["fail_closed"],
        },
        "upstream": {
            "source": item["upstream_source"],
            "status": item["upstream_status"],
        },
        "evidence": {
            "manifest_sha256": item["manifest_sha256"],
            "reasons": item["reasons"],
            "raw_result": item["result"],
        },
        "verification_policy": {
            "invalid_input": "reject",
            "missing_data": "reject",
            "upstream_failure": "reject",
            "silent_success": False,
        },
    }

    canonical = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    report_sha256 = sha256_text(canonical)

    return {
        "report": report,
        "report_sha256": report_sha256,
        "canonical_json": canonical,
    }


def save_report_files(result_id: int) -> dict[str, Any] | None:
    package = build_report_package(result_id)
    if package is None:
        return None

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    base = REPORT_DIR / f"stage297_report_{result_id}"

    json_path = base.with_suffix(".json")
    sha_path = base.with_suffix(".sha256")
    html_path = base.with_suffix(".html")

    pretty_json = json.dumps(package["report"], ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    json_path.write_text(pretty_json, encoding="utf-8")
    sha_path.write_text(f'{package["report_sha256"]}  {json_path.name}\n', encoding="utf-8")

    report = package["report"]
    reasons = report["evidence"]["reasons"]
    reasons_html = "\n".join(
        f"<li><strong>{r.get('item')}</strong>: {r.get('message')} ({'ok' if r.get('ok') else 'ng'})</li>"
        for r in reasons
    )

    html = f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <title>Stage297 Verification Report #{result_id}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; line-height: 1.6; }}
    code {{ word-break: break-all; }}
    .box {{ border: 1px solid #ccc; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
    .decision {{ font-size: 28px; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>Stage297 Verification Report Package</h1>
  <div class="box">
    <div class="decision">{report["decision"]["decision"].upper()}</div>
    <div>Trust Score: {report["decision"]["trust_score"]}</div>
    <div>Fail-Closed: {report["decision"]["fail_closed"]}</div>
  </div>
  <div class="box">
    <h2>Subject</h2>
    <div>Result ID: {report["subject"]["result_id"]}</div>
    <div>Input URL: <code>{report["subject"]["input_url"]}</code></div>
    <div>Created At: {report["subject"]["created_at"]}</div>
  </div>
  <div class="box">
    <h2>Upstream</h2>
    <div>Source: {report["upstream"]["source"]}</div>
    <div>Status: {report["upstream"]["status"]}</div>
  </div>
  <div class="box">
    <h2>Evidence</h2>
    <div>Manifest SHA-256: <code>{report["evidence"]["manifest_sha256"]}</code></div>
    <h3>Reasons</h3>
    <ul>{reasons_html}</ul>
  </div>
  <div class="box">
    <h2>Report Proof</h2>
    <div>Report SHA-256: <code>{package["report_sha256"]}</code></div>
  </div>
</body>
</html>
"""
    html_path.write_text(html, encoding="utf-8")

    return {
        "json_path": str(json_path),
        "sha256_path": str(sha_path),
        "html_path": str(html_path),
        "report_sha256": package["report_sha256"],
    }


@app.route("/")
def index():
    return render_template("index.html", stage289_verify_url=STAGE289_VERIFY_URL)


@app.route("/api/health")
def health():
    return jsonify({
        "ok": True,
        "stage": 297,
        "storage": "sqlite",
        "integration": "stage289",
        "dashboard": True,
        "report_package": True,
        "export": ["json", "csv", "report-json", "report-html", "report-sha256"],
        "db_path": str(DB_PATH.name),
        "stage289_verify_url": STAGE289_VERIFY_URL,
    })


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    input_url = str(data.get("url", "")).strip()
    manifest_text = str(data.get("manifest", "")).strip()

    upstream = call_stage289_verify(input_url, manifest_text)
    result = upstream["result"] if upstream["ok"] else build_fail_closed_error_result(
        manifest_text=manifest_text,
        message=upstream["message"],
        body=upstream.get("body", ""),
    )

    row_id = save_result(input_url, manifest_text, result)

    return jsonify({
        "ok": True,
        "saved": True,
        "id": row_id,
        "upstream_ok": upstream["ok"],
        "upstream_error": None if upstream["ok"] else {
            "type": upstream["error_type"],
            "status_code": upstream["status_code"],
            "message": upstream["message"],
        },
        "result": result,
    })


@app.route("/api/results", methods=["GET"])
def api_results():
    decision, url_query, min_score, limit = parse_filters(request.args)
    items = query_results(decision, url_query, min_score, limit)

    return jsonify({
        "ok": True,
        "filters": {
            "decision": decision,
            "url_query": url_query,
            "min_score": min_score,
            "limit": limit,
        },
        "count": len(items),
        "items": items,
    })


@app.route("/api/results/<int:result_id>", methods=["GET"])
def api_result_detail(result_id: int):
    item = get_result_row(result_id)
    if item is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "item": item})


@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    return jsonify({"ok": True, "stage": 297, "dashboard": query_dashboard_summary()})


@app.route("/api/export/json", methods=["GET"])
def api_export_json():
    decision, url_query, min_score, limit = parse_filters(request.args)
    items = query_results(decision, url_query, min_score, limit)
    payload = {
        "exported_at": utc_now_iso(),
        "stage": 297,
        "integration": "stage289",
        "filters": {
            "decision": decision,
            "url_query": url_query,
            "min_score": min_score,
            "limit": limit,
        },
        "count": len(items),
        "items": items,
    }
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        mimetype="application/json",
        headers={"Content-Disposition": 'attachment; filename="stage297_export.json"'},
    )


@app.route("/api/export/csv", methods=["GET"])
def api_export_csv():
    decision, url_query, min_score, limit = parse_filters(request.args)
    items = query_results(decision, url_query, min_score, limit)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "created_at", "input_url", "manifest_sha256", "decision",
        "trust_score", "fail_closed", "upstream_source", "upstream_status",
    ])

    for item in items:
        writer.writerow([
            item["id"], item["created_at"], item["input_url"], item["manifest_sha256"],
            item["decision"], item["trust_score"], item["fail_closed"],
            item["upstream_source"], item["upstream_status"],
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="stage297_export.csv"'},
    )


@app.route("/api/report/<int:result_id>", methods=["GET"])
def api_report(result_id: int):
    package = build_report_package(result_id)
    if package is None:
        return jsonify({"ok": False, "error": "not_found"}), 404

    return jsonify({
        "ok": True,
        "stage": 297,
        "report_sha256": package["report_sha256"],
        "report": package["report"],
    })


@app.route("/api/report/<int:result_id>/json", methods=["GET"])
def api_report_json(result_id: int):
    package = build_report_package(result_id)
    if package is None:
        return jsonify({"ok": False, "error": "not_found"}), 404

    return Response(
        json.dumps(package["report"], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="stage297_report_{result_id}.json"'},
    )


@app.route("/api/report/<int:result_id>/sha256", methods=["GET"])
def api_report_sha256(result_id: int):
    package = build_report_package(result_id)
    if package is None:
        return jsonify({"ok": False, "error": "not_found"}), 404

    filename = f"stage297_report_{result_id}.json"
    return Response(
        f'{package["report_sha256"]}  {filename}\n',
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="stage297_report_{result_id}.sha256"'},
    )


@app.route("/api/report/<int:result_id>/save", methods=["POST"])
def api_report_save(result_id: int):
    saved = save_report_files(result_id)
    if saved is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "stage": 297, "saved": saved})


@app.route("/report/<int:result_id>", methods=["GET"])
def report_html(result_id: int):
    package = build_report_package(result_id)
    if package is None:
        return "not found", 404

    report = package["report"]
    reasons = report["evidence"]["reasons"]
    return render_template(
        "report.html",
        report=report,
        report_sha256=package["report_sha256"],
        reasons=reasons,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "2970"))
    init_db()
    app.run(host="0.0.0.0", port=port, debug=False)
