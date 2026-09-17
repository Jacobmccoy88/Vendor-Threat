"use strict";

// ── DOM refs ───────────────────────────────────────────────────────────────
const vendorInput   = document.getElementById("vendor-input");
const scanBtn       = document.getElementById("scan-btn");
const statusBar     = document.getElementById("status-bar");
const statusText    = document.getElementById("status-text");
const results       = document.getElementById("results");
const riskLevel     = document.getElementById("risk-level");
const statCritical  = document.getElementById("stat-critical");
const statHigh      = document.getElementById("stat-high");
const statMedium    = document.getElementById("stat-medium");
const statLow       = document.getElementById("stat-low");
const scanMeta      = document.getElementById("scan-meta");
const patternRow    = document.getElementById("pattern-row");
const patternTags   = document.getElementById("pattern-tags");
const sourcePills   = document.getElementById("source-pills");
const sourceStatusBar = document.getElementById("source-status-bar");
const findingsList  = document.getElementById("findings-list");
const noResults     = document.getElementById("no-results");

// ── Load sources on startup ────────────────────────────────────────────────
fetch("/sources")
  .then(r => r.json())
  .then(sources => {
    sourcePills.innerHTML = sources
      .map(s => `<span class="source-pill">${s.name}</span>`)
      .join("");
  })
  .catch(() => {
    sourcePills.textContent = "unavailable";
  });

// ── Scan ───────────────────────────────────────────────────────────────────
function runScan() {
  const vendor = vendorInput.value.trim();
  if (!vendor) {
    vendorInput.focus();
    return;
  }

  setScanning(true);
  clearResults();

  const messages = [
    `Scanning for "${vendor}" across cybersecurity sources…`,
    "Querying breach databases…",
    "Checking CISA KEV feed…",
    "Applying regex pattern matching…",
  ];
  let msgIdx = 0;
  statusText.textContent = messages[0];
  const msgInterval = setInterval(() => {
    msgIdx = (msgIdx + 1) % messages.length;
    statusText.textContent = messages[msgIdx];
  }, 2500);

  fetch("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ vendor }),
  })
    .then(r => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    })
    .then(data => {
      clearInterval(msgInterval);
      setScanning(false);
      renderResults(data);
    })
    .catch(err => {
      clearInterval(msgInterval);
      setScanning(false);
      statusText.textContent = `Scan failed: ${err.message}`;
      statusBar.classList.remove("hidden");
    });
}

// ── Render ─────────────────────────────────────────────────────────────────
function renderResults(data) {
  results.classList.remove("hidden");

  const summary = data.risk_summary;

  // Risk level
  riskLevel.textContent = summary.overall_risk;
  riskLevel.className = `risk-level ${summary.overall_risk}`;

  // Stat counts
  statCritical.textContent = summary.CRITICAL || 0;
  statHigh.textContent     = summary.HIGH     || 0;
  statMedium.textContent   = summary.MEDIUM   || 0;
  statLow.textContent      = summary.LOW      || 0;

  // Meta
  scanMeta.innerHTML =
    `<strong>${data.total_findings}</strong> finding${data.total_findings !== 1 ? "s" : ""}<br>` +
    `Scanned in ${data.scan_time}s<br>` +
    `${formatTimestamp(data.timestamp)}`;

  // Top patterns
  if (summary.top_patterns && summary.top_patterns.length > 0) {
    patternRow.classList.remove("hidden");
    patternTags.innerHTML = summary.top_patterns
      .map(p => `<span class="pattern-tag">${formatPatternLabel(p)}</span>`)
      .join("");
  }

  // Source statuses
  if (data.source_statuses && data.source_statuses.length > 0) {
    sourceStatusBar.innerHTML = data.source_statuses
      .map(s =>
        `<span class="source-status-pill ${s.status}">
          <span class="dot"></span>
          ${s.name}${s.count > 0 ? ` (${s.count})` : ""}
        </span>`
      )
      .join("");
  }

  // Findings
  if (data.findings && data.findings.length > 0) {
    findingsList.innerHTML = data.findings.map(renderFinding).join("");
    noResults.classList.add("hidden");
  } else {
    noResults.classList.remove("hidden");
  }
}

function renderFinding(f) {
  const patterns = (f.matched_patterns || [])
    .map(p => `<span class="pattern-badge">${formatPatternLabel(p)}</span>`)
    .join("");

  const titleEl = f.url
    ? `<a href="${escHtml(f.url)}" target="_blank" rel="noopener noreferrer">${escHtml(f.title)}</a>`
    : escHtml(f.title);

  const snippet = f.snippet
    ? `<p class="finding-snippet">${escHtml(f.snippet.slice(0, 280))}${f.snippet.length > 280 ? "…" : ""}</p>`
    : "";

  return `
    <div class="finding-card ${f.severity_label}">
      <div class="finding-header">
        <span class="finding-severity ${f.severity_label}">${f.severity_label}</span>
        <span class="finding-title">${titleEl}</span>
      </div>
      <div class="finding-meta">
        <span class="finding-source">⬡ ${escHtml(f.source)} · ${escHtml(f.category)}</span>
        ${f.url ? `<span class="finding-source">${escHtml(truncateUrl(f.url))}</span>` : ""}
      </div>
      ${snippet}
      ${patterns ? `<div class="finding-patterns">${patterns}</div>` : ""}
    </div>
  `;
}

// ── Helpers ────────────────────────────────────────────────────────────────
function setScanning(active) {
  scanBtn.disabled = active;
  statusBar.classList.toggle("hidden", !active);
  if (!active) statusText.textContent = "";
}

function clearResults() {
  results.classList.add("hidden");
  findingsList.innerHTML = "";
  sourceStatusBar.innerHTML = "";
  patternTags.innerHTML = "";
  patternRow.classList.add("hidden");
  noResults.classList.add("hidden");
}

function formatPatternLabel(key) {
  return key.replace(/_/g, " ");
}

function formatTimestamp(iso) {
  try {
    return new Date(iso).toLocaleString("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function truncateUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    return url.slice(0, 40);
  }
}

function escHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Events ─────────────────────────────────────────────────────────────────
scanBtn.addEventListener("click", runScan);
vendorInput.addEventListener("keydown", e => {
  if (e.key === "Enter") runScan();
});