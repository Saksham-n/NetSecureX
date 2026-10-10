/**
 * NetSecureX Extension — Popup JavaScript
 * Handles tab switching, URL scanning, email analysis, and page link inspection.
 */

const API_BASE = "http://127.0.0.1:5000";

// ─── Utilities ─────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const show = el => el.classList.remove("hidden");
const hide = el => el.classList.add("hidden");

function setLoading(btn, isLoading, label = "Scan") {
  btn.disabled = isLoading;
  btn.innerHTML = isLoading
    ? `<span class="spinner"></span> Scanning…`
    : `<span class="btn-icon">${label.icon || "🔍"}</span> ${label.text || label}`;
}

function riskBadgeHTML(riskLevel) {
  const map = {
    HIGH:   { cls: "badge-high",   icon: "🔴", label: "HIGH RISK" },
    MEDIUM: { cls: "badge-medium", icon: "🟡", label: "MEDIUM RISK" },
    LOW:    { cls: "badge-low",    icon: "🟢", label: "LOW RISK" },
  };
  const r = map[riskLevel] || map.LOW;
  return `<span class="risk-badge ${r.cls}">${r.icon} ${r.label}</span>`;
}

function setCardRisk(card, riskLevel) {
  card.classList.remove("risk-high", "risk-medium", "risk-low");
  if (riskLevel) card.classList.add(`risk-${riskLevel.toLowerCase()}`);
}

async function apiPost(endpoint, payload) {
  const resp = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(`Server returned HTTP ${resp.status}`);
  return resp.json();
}

// ─── Server Status Ping ────────────────────────────────────────────────────
async function checkServerStatus() {
  const dot = $("server-status");
  try {
    const resp = await fetch(`${API_BASE}/api/logs`, { method: "GET" });
    if (resp.ok) {
      dot.className = "status-dot status-online";
      dot.title = "NetSecureX server online";
    } else {
      throw new Error("not ok");
    }
  } catch {
    dot.className = "status-dot status-offline";
    dot.title = "NetSecureX server offline — start app.py";
  }
}

// ─── Tab Switching ─────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    tab.classList.add("active");
    $(`tab-content-${tab.dataset.tab}`).classList.add("active");
  });
});

// ─── URL SCAN TAB ──────────────────────────────────────────────────────────
$("btn-scan-page-url").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) $("url-input").value = tab.url;
});

$("btn-scan-url").addEventListener("click", async () => {
  const url = $("url-input").value.trim();
  if (!url) return;

  const btn = $("btn-scan-url");
  const resultCard = $("url-result");
  const errBox = $("url-error");

  setLoading(btn, true, "Scan URL");
  hide(resultCard);
  hide(errBox);

  try {
    const result = await apiPost("/api/scan_url", { url });

    // Populate result card
    $("url-risk-badge").innerHTML = riskBadgeHTML(result.risk_level);
    $("url-score").textContent = `Score: —`;
    $("url-domain").textContent = result.domain || url;
    $("url-details").textContent = result.details || (result.is_malicious ? `Flagged as ${result.threat_type}` : "No threats detected by Safe Browsing");

    // Tags for suspicious patterns
    const tagsEl = $("url-tags");
    tagsEl.innerHTML = "";
    (result.suspicious_patterns || []).forEach(p => {
      const span = document.createElement("span");
      span.className = "result-tag";
      span.textContent = p;
      tagsEl.appendChild(span);
    });

    setCardRisk(resultCard, result.risk_level);
    show(resultCard);
  } catch (err) {
    errBox.textContent = `❌ ${err.message} — Is app.py running on port 5000?`;
    show(errBox);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="btn-icon">🔍</span> Scan URL`;
  }
});

// Allow Enter key in URL input
$("url-input").addEventListener("keydown", e => {
  if (e.key === "Enter") $("btn-scan-url").click();
});

// ─── EMAIL SCAN TAB ────────────────────────────────────────────────────────
$("btn-scan-email").addEventListener("click", async () => {
  const fromAddress = $("email-from").value.trim();
  const displayName = $("email-display").value.trim();
  const subject = $("email-subject").value.trim();
  const body = $("email-body").value.trim();
  const urlsRaw = $("email-urls").value.trim();
  const urls = urlsRaw ? urlsRaw.split("\n").map(u => u.trim()).filter(u => u.startsWith("http")) : [];

  if (!fromAddress && !subject && !body) {
    const errBox = $("email-error");
    errBox.textContent = "⚠️ Please fill in at least From Address, Subject, or Body.";
    show(errBox);
    return;
  }

  const btn = $("btn-scan-email");
  const resultCard = $("email-result");
  const errBox = $("email-error");

  setLoading(btn, true);
  hide(resultCard);
  hide(errBox);

  try {
    const result = await apiPost("/api/scan_email", {
      display_name: displayName,
      from_address: fromAddress,
      subject,
      body,
      urls,
    });

    $("email-risk-badge").innerHTML = riskBadgeHTML(result.risk_level);
    $("email-score").textContent = `Score: ${result.total_score}/100`;

    // Threat chips
    const chipsEl = $("email-threat-chips");
    chipsEl.innerHTML = "";
    if (result.urgency_detected)       addChip(chipsEl, "⚡ Urgency Language", "chip-urgency");
    if (result.display_name_spoofed)   addChip(chipsEl, "🎭 Display Name Spoofing", "chip-spoof");
    if (result.lookalike_detected)     addChip(chipsEl, "🔗 Lookalike Domain", "chip-lookalike");
    if (result.url_results?.some(u => u.is_malicious)) addChip(chipsEl, "☠️ Malicious URL", "chip-malurl");
    if (!result.urgency_detected && !result.display_name_spoofed && !result.lookalike_detected && !result.url_results?.some(u => u.is_malicious)) {
      addChip(chipsEl, "✓ No Threats Detected", "chip-clean");
    }

    // Details / reasons
    const detailsEl = $("email-details");
    if (result.reasons?.length) {
      detailsEl.innerHTML = result.reasons.map(r => `• ${r}`).join("<br>");
    } else {
      detailsEl.textContent = "No specific threat indicators found.";
    }

    // URL results list
    const urlListEl = $("email-url-list");
    urlListEl.innerHTML = "";
    if (result.url_results?.length) {
      result.url_results.forEach(u => {
        const row = document.createElement("div");
        row.className = "url-item";
        row.innerHTML = `
          <span class="url-item-domain" title="${u.url}">${u.domain || u.url}</span>
          <span class="url-item-risk url-risk-${u.risk.toLowerCase()}">${u.risk}</span>
        `;
        urlListEl.appendChild(row);
      });
    }

    setCardRisk(resultCard, result.risk_level);
    show(resultCard);
  } catch (err) {
    errBox.textContent = `❌ ${err.message} — Is app.py running on port 5000?`;
    show(errBox);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="btn-icon">🔬</span> Analyse Email`;
  }
});

function addChip(container, label, cls) {
  const span = document.createElement("span");
  span.className = `chip ${cls}`;
  span.textContent = label;
  container.appendChild(span);
}

// ─── PAGE INFO TAB ─────────────────────────────────────────────────────────
async function loadPageInfo() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const anchors = Array.from(document.querySelectorAll("a[href]"));
        const external = anchors.filter(a => {
          try {
            const u = new URL(a.href);
            return u.hostname !== location.hostname && u.protocol.startsWith("http");
          } catch { return false; }
        });
        const scanned = external.filter(a => a.hasAttribute("data-nsx-scanned") && a.getAttribute("data-nsx-scanned") !== "pending");
        const highRisk = external.filter(a => a.getAttribute("data-nsx-scanned") === "HIGH").length;
        const medRisk  = external.filter(a => a.getAttribute("data-nsx-scanned") === "MEDIUM").length;
        const linkData = external.slice(0, 30).map(a => ({
          url: a.href,
          domain: (() => { try { return new URL(a.href).hostname; } catch { return a.href; } })(),
          risk: a.getAttribute("data-nsx-scanned") || "pending",
        }));
        return { total: external.length, scanned: scanned.length, highRisk, medRisk, linkData };
      },
    });

    const data = results?.[0]?.result;
    if (!data) return;

    $("stat-links-val").textContent = data.total;
    $("stat-scanned-val").textContent = data.scanned;

    let overallRisk = "LOW";
    if (data.highRisk > 0) overallRisk = "HIGH";
    else if (data.medRisk > 0) overallRisk = "MEDIUM";
    const riskColors = { HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#10b981" };
    $("stat-risk-val").textContent = overallRisk;
    $("stat-risk-val").style.color = riskColors[overallRisk];

    const listEl = $("page-links-list");
    listEl.innerHTML = "";
    data.linkData.forEach(link => {
      const risk = ["HIGH","MEDIUM","LOW"].includes(link.risk) ? link.risk : "LOW";
      const row = document.createElement("div");
      row.className = "link-row";
      row.innerHTML = `
        <span class="url-item-domain link-row-url" title="${link.url}">${link.domain}</span>
        <span class="url-item-risk url-risk-${risk.toLowerCase()}">${link.risk === "pending" ? "…" : risk}</span>
      `;
      listEl.appendChild(row);
    });
  } catch (err) {
    // scripting API not available on restricted pages
  }
}

$("btn-scan-all-links").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        // Trigger content script re-scan by dispatching a DOM event
        document.dispatchEvent(new Event("nsx-rescan"));
      },
    });
    setTimeout(loadPageInfo, 1500);
  } catch {}
});

// ─── Init ──────────────────────────────────────────────────────────────────
checkServerStatus();
loadPageInfo();
