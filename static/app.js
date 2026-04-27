const urlInput = document.getElementById("url");
const manifestInput = document.getElementById("manifest");
const verifyBtn = document.getElementById("verifyBtn");
const sampleBtn = document.getElementById("sampleBtn");

const decisionFilter = document.getElementById("decisionFilter");
const urlQueryInput = document.getElementById("urlQuery");
const minScoreInput = document.getElementById("minScore");
const limitInput = document.getElementById("limit");
const searchBtn = document.getElementById("searchBtn");
const clearBtn = document.getElementById("clearBtn");

const exportJsonLink = document.getElementById("exportJsonLink");
const exportCsvLink = document.getElementById("exportCsvLink");

const resultCard = document.getElementById("resultCard");
const historyMeta = document.getElementById("historyMeta");
const historyBox = document.getElementById("history");

const metricTotal = document.getElementById("metricTotal");
const metricAcceptRate = document.getElementById("metricAcceptRate");
const metricRejectRate = document.getElementById("metricRejectRate");
const metricUpstreamErrorRate = document.getElementById("metricUpstreamErrorRate");
const metricAverageScore = document.getElementById("metricAverageScore");

const decisionSummary = document.getElementById("decisionSummary");
const upstreamSummary = document.getElementById("upstreamSummary");
const scoreDistribution = document.getElementById("scoreDistribution");

function decisionClass(decision) {
  if (decision === "accept") return "accept";
  if (decision === "pending") return "pending";
  return "reject";
}

function renderResult(result, id = null) {
  const reasonsHtml = (result.reasons || []).map(item => `
    <li class="${item.ok ? "ok" : "ng"}">
      <strong>${item.item}</strong>: ${item.message}
    </li>
  `).join("");

  const reportLinks = id ? `
    <div class="actions export-actions">
      <a href="/report/${id}" target="_blank">HTMLレポート</a>
      <a href="/api/report/${id}/json" target="_blank">Report JSON</a>
      <a href="/api/report/${id}/sha256" target="_blank">Report SHA256</a>
      <button type="button" onclick="saveReport(${id})">レポートを保存</button>
    </div>
  ` : "";

  resultCard.className = `result-card ${decisionClass(result.decision)}`;
  resultCard.innerHTML = `
    <div class="result-head">
      <span class="decision ${decisionClass(result.decision)}">${String(result.decision || "reject").toUpperCase()}</span>
      <span class="score">Trust Score: ${Number(result.trust_score || 0).toFixed(3)}</span>
      ${id ? `<span class="saved-id">Saved ID: ${id}</span>` : ""}
    </div>
    <div class="meta">
      <div><strong>Fail-Closed:</strong> ${result.fail_closed ? "true" : "false"}</div>
      <div><strong>Manifest SHA-256:</strong> <code>${result.manifest_sha256 || ""}</code></div>
      <div><strong>Verified At:</strong> ${result.verified_at || ""}</div>
      <div><strong>Upstream Source:</strong> ${result.upstream_source || "-"}</div>
      <div><strong>Upstream Status:</strong> ${result.upstream_status || "-"}</div>
    </div>
    <ul class="reason-list">${reasonsHtml}</ul>
    ${reportLinks}
  `;
}

async function verifyAndSave() {
  const payload = { url: urlInput.value, manifest: manifestInput.value };

  const res = await fetch("/api/verify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  if (!data.ok) {
    alert("検証に失敗しました。");
    return;
  }

  renderResult(data.result, data.id);
  await loadHistory();
  await loadDashboard();
}

function buildQueryString() {
  const params = new URLSearchParams();

  if (decisionFilter.value) params.set("decision", decisionFilter.value);
  if (urlQueryInput.value.trim()) params.set("url_query", urlQueryInput.value.trim());
  if (minScoreInput.value.trim()) params.set("min_score", minScoreInput.value.trim());
  params.set("limit", limitInput.value.trim() || "20");

  return params.toString();
}

function updateExportLinks() {
  const query = buildQueryString();
  exportJsonLink.href = `/api/export/json?${query}`;
  exportCsvLink.href = `/api/export/csv?${query}`;
}

async function loadHistory() {
  const query = buildQueryString();
  updateExportLinks();

  const res = await fetch(`/api/results?${query}`);
  const data = await res.json();

  if (!data.ok || !data.items.length) {
    historyMeta.textContent = "一致する履歴はありません。";
    historyBox.innerHTML = `<div class="history-empty">条件に一致する履歴はありません。</div>`;
    resultCard.className = "result-card empty";
    resultCard.innerHTML = "まだ検証結果はありません。";
    return;
  }

  historyMeta.textContent =
    `件数: ${data.count} / decision=${data.filters.decision || "all"} / ` +
    `url_query=${data.filters.url_query || "-"} / ` +
    `min_score=${data.filters.min_score ?? "-"} / limit=${data.filters.limit}`;

  historyBox.innerHTML = data.items.map(item => `
    <div class="history-item">
      <div class="history-top">
        <span class="decision ${decisionClass(item.decision)}">${item.decision.toUpperCase()}</span>
        <span class="score">${Number(item.trust_score).toFixed(3)}</span>
      </div>
      <div><strong>ID:</strong> ${item.id}</div>
      <div><strong>URL:</strong> ${escapeHtml(item.input_url)}</div>
      <div><strong>Time:</strong> ${item.created_at}</div>
      <div><strong>SHA-256:</strong> <code>${item.manifest_sha256}</code></div>
      <div><strong>Upstream:</strong> ${item.upstream_source} / ${item.upstream_status}</div>
      <div class="actions export-actions">
        <button type="button" onclick="loadDetail(${item.id})">詳細表示</button>
        <a href="/report/${item.id}" target="_blank">HTMLレポート</a>
        <a href="/api/report/${item.id}/json" target="_blank">JSON</a>
        <a href="/api/report/${item.id}/sha256" target="_blank">SHA256</a>
      </div>
    </div>
  `).join("");

  await loadDetail(data.items[0].id);
}

async function loadDetail(id) {
  const res = await fetch(`/api/results/${id}`);
  const data = await res.json();
  if (!data.ok) {
    alert("詳細取得に失敗しました。");
    return;
  }
  renderResult(data.item.result, data.item.id);
  urlInput.value = data.item.input_url;
  manifestInput.value = data.item.manifest_text;
}

async function saveReport(id) {
  const res = await fetch(`/api/report/${id}/save`, { method: "POST" });
  const data = await res.json();
  if (!data.ok) {
    alert("レポート保存に失敗しました。");
    return;
  }
  alert(`レポート保存完了\nSHA256: ${data.saved.report_sha256}`);
}

async function loadDashboard() {
  const res = await fetch("/api/dashboard");
  const data = await res.json();
  if (!data.ok) return;

  const d = data.dashboard;

  metricTotal.textContent = d.total_results;
  metricAcceptRate.textContent = `${d.decision_rates.accept_rate}%`;
  metricRejectRate.textContent = `${d.decision_rates.reject_rate}%`;
  metricUpstreamErrorRate.textContent = `${d.upstream_rates.upstream_error_rate}%`;
  metricAverageScore.textContent = Number(d.trust_score.average).toFixed(3);

  decisionSummary.innerHTML = `
    <div>accept: ${d.decision_counts.accept}</div>
    <div>pending: ${d.decision_counts.pending}</div>
    <div>reject: ${d.decision_counts.reject}</div>
  `;

  upstreamSummary.innerHTML = `
    <div>ok: ${d.upstream_counts.ok}</div>
    <div>error: ${d.upstream_counts.error}</div>
    <div>unknown: ${d.upstream_counts.unknown}</div>
  `;

  scoreDistribution.innerHTML = Object.entries(d.trust_score.distribution)
    .map(([label, count]) => `<div>${label}: ${count}</div>`)
    .join("");
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function loadSample() {
  urlInput.value = "https://example.com/verify";
  manifestInput.value = JSON.stringify({
    url: "https://example.com/verify",
    subject: { type: "verification_target", name: "sample artifact" },
    evidence: [
      { type: "sha256", ok: true },
      { type: "github_actions_receipt", ok: true }
    ],
    verification_policy: { fail_closed: true }
  }, null, 2);
}

function clearFilters() {
  decisionFilter.value = "";
  urlQueryInput.value = "";
  minScoreInput.value = "";
  limitInput.value = "20";
  updateExportLinks();
  loadHistory();
}

verifyBtn.addEventListener("click", verifyAndSave);
sampleBtn.addEventListener("click", loadSample);
searchBtn.addEventListener("click", loadHistory);
clearBtn.addEventListener("click", clearFilters);

decisionFilter.addEventListener("change", updateExportLinks);
urlQueryInput.addEventListener("input", updateExportLinks);
minScoreInput.addEventListener("input", updateExportLinks);
limitInput.addEventListener("input", updateExportLinks);

updateExportLinks();
loadDashboard();
loadHistory();
