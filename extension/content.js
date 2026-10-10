/**
 * NetSecureX Extension — Content Script (v2)
 * ============================================
 * Features:
 *  1. Scans all external links with visual risk badges + tooltips
 *  2. LOCAL heuristic fallback (works fully offline without the server)
 *  3. Gmail + Outlook webmail auto-detection (handles SPA navigation)
 *  4. Sticky email threat banner with drill-down details
 *  5. Handles DOM mutations from SPAs (Gmail, Outlook are React/Angular apps)
 *  6. Rate-limited batch scanning to avoid hammering the API
 *  7. Re-scan triggered by popup via 'nsx-rescan' DOM event
 */

(function () {
  "use strict";

  // ─── Constants ────────────────────────────────────────────────────────────
  const NSX_ATTR          = "data-nsx-scanned";
  const NSX_BADGE_CLASS   = "nsx-link-badge";
  const SCAN_BATCH_SIZE   = 10;        // URLs per API call batch
  const SCAN_DELAY_MS     = 900;       // Debounce delay for DOM mutations
  const EMAIL_SCAN_DELAY  = 1400;      // Debounce for email detection
  const MAX_LINKS_PER_PAGE = 100;      // Safety cap

  // ─── Local Heuristics (offline capable) ──────────────────────────────────
  const SUSPICIOUS_TLDS = new Set([
    ".top", ".xyz", ".work", ".click", ".link", ".buzz", ".cam", ".rest",
    ".gq", ".ml", ".cf", ".tk", ".pw", ".cc", ".ru", ".su", ".ws",
  ]);

  const PHISHING_KEYWORDS = [
    "verify-account", "update-bank", "reset-password-now", "confirm-identity",
    "login?redirect=", "signin?next=", "account-suspended", "security-alert",
    "paypal-secure", "apple-id-verify", "microsoft-account-alert",
    "your-account-has-been", "click-here-to-verify", "unusual-activity",
  ];

  const URGENCY_KEYWORDS = [
    "urgent action required", "immediate response needed", "account suspended",
    "wire transfer", "gift card", "verify your password", "payroll direct deposit",
    "unauthorized sign-in attempt", "final warning", "overdue invoice",
    "crypto payment", "act now", "expires today", "limited time", "click immediately",
    "your account will be", "confirm your identity", "unusual activity detected",
  ];

  const VIP_NAMES = [
    "ceo", "chief executive officer", "finance director", "payroll dept",
    "hr department", "it helpdesk", "security administrator", "cfo",
    "chief financial officer", "president", "managing director",
  ];

  // ─── Local URL Heuristic Scan ─────────────────────────────────────────────
  function localScanUrl(url) {
    const findings = [];
    let score = 0;

    let domain = "";
    try {
      const parsed = new URL(url);
      domain = parsed.hostname.toLowerCase();

      // Raw IP address
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
        findings.push("URL uses raw IP address instead of hostname");
        score += 40;
      }

      // Punycode / IDN
      if (domain.includes("xn--")) {
        findings.push("URL uses punycode/internationalized domain (possible homoglyph attack)");
        score += 30;
      }

      // Excessive subdomain depth
      const parts = domain.split(".");
      if (parts.length >= 4) {
        findings.push("Excessive subdomain depth (possible brand masquerading)");
        score += 20;
      }

      // Suspicious TLDs
      for (const tld of SUSPICIOUS_TLDS) {
        if (domain.endsWith(tld)) {
          findings.push(`High-abuse top-level domain: ${tld}`);
          score += 15;
          break;
        }
      }

      // Phishing path/query patterns
      const fullLower = url.toLowerCase();
      for (const kw of PHISHING_KEYWORDS) {
        if (fullLower.includes(kw)) {
          findings.push(`Suspicious credential harvesting pattern: "${kw}"`);
          score += 25;
          break;
        }
      }

      // Brand name in domain but not the real domain
      const BRANDS = ["paypal", "microsoft", "apple", "google", "amazon", "netflix",
                      "facebook", "instagram", "twitter", "linkedin", "dropbox",
                      "chase", "wellsfargo", "bankofamerica", "citibank"];
      for (const brand of BRANDS) {
        if (domain.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.net`)) {
          findings.push(`Brand impersonation: "${brand}" found in non-official domain`);
          score += 35;
          break;
        }
      }

    } catch (e) {
      findings.push("Malformed URL");
      score += 10;
    }

    const risk = score >= 60 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW";
    return { url, domain, findings, score, risk, source: "local" };
  }

  // ─── Local Email Heuristic Scan ───────────────────────────────────────────
  function localScanEmail({ display_name = "", from_address = "", subject = "", body = "", urls = [] }) {
    const reasons = [];
    let score = 0;

    const fromDomain = from_address.includes("@") ? from_address.split("@")[1].toLowerCase() : "";
    const textLower = `${subject} ${body}`.toLowerCase();
    const dispLower = display_name.toLowerCase();

    // 1. Urgency language
    const urgencyHits = URGENCY_KEYWORDS.filter(kw => textLower.includes(kw));
    if (urgencyHits.length) {
      score += Math.min(15 + (urgencyHits.length - 1) * 5, 30);
      reasons.push(`Urgency language detected: ${urgencyHits.slice(0, 3).join(", ")}`);
    }

    // 2. VIP/executive impersonation
    const vipHit = VIP_NAMES.find(v => dispLower.includes(v));
    if (vipHit) {
      const freemails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"];
      if (freemails.some(f => fromDomain.endsWith(f))) {
        score += 45;
        reasons.push(`Executive impersonation: "${display_name}" sending from freemail (${fromDomain})`);
      }
    }

    // 3. URL heuristics in email
    let maxUrlRisk = "LOW";
    for (const u of (urls || []).slice(0, 20)) {
      const res = localScanUrl(u);
      if (res.risk === "HIGH")        { score += 40; maxUrlRisk = "HIGH"; }
      else if (res.risk === "MEDIUM") { score += 15; if (maxUrlRisk !== "HIGH") maxUrlRisk = "MEDIUM"; }
      if (res.findings.length) reasons.push(`URL: ${res.domain} — ${res.findings[0]}`);
    }

    // 4. Sender domain suspicious
    if (fromDomain) {
      const localUrlRes = localScanUrl(`https://${fromDomain}`);
      if (localUrlRes.risk !== "LOW") {
        score += 20;
        reasons.push(`Suspicious sender domain: ${fromDomain}`);
      }
    }

    score = Math.min(score, 100);
    const risk = score >= 70 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW";

    return {
      risk_level: risk,
      total_score: score,
      urgency_detected: urgencyHits.length > 0,
      urgency_matches: urgencyHits,
      display_name_spoofed: !!vipHit,
      display_name_reason: vipHit ? `"${display_name}" from ${fromDomain}` : "",
      lookalike_detected: false,
      reasons,
      url_results: (urls || []).map(u => { const r = localScanUrl(u); return { url: r.url, domain: r.domain, is_malicious: r.risk === "HIGH", suspicious_patterns: r.findings, risk: r.risk }; }),
      source: "local",
    };
  }

  // ─── Inject Styles ────────────────────────────────────────────────────────
  function injectStyles() {
    if (document.getElementById("nsx-content-styles")) return;
    const s = document.createElement("style");
    s.id = "nsx-content-styles";
    s.textContent = `
      .nsx-link-badge {
        display: inline-block;
        font-size: 10px;
        font-weight: 700;
        font-family: system-ui, 'Inter', sans-serif;
        border-radius: 4px;
        padding: 1px 5px;
        margin-left: 4px;
        vertical-align: middle;
        cursor: default;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        line-height: 16px;
        animation: nsx-pop 0.2s ease;
        user-select: none;
        flex-shrink: 0;
      }
      @keyframes nsx-pop {
        0%   { transform: scale(0.6); opacity: 0; }
        100% { transform: scale(1);   opacity: 1; }
      }
      .nsx-badge-high   { background: #ef4444; color: #fff; }
      .nsx-badge-medium { background: #f59e0b; color: #111; }
      .nsx-badge-low    { background: #10b981; color: #fff; }
      .nsx-badge-scan   { background: #3b82f6; color: #fff; opacity: 0.7; }

      /* Tooltip */
      #nsx-tooltip {
        position: fixed;
        z-index: 2147483647;
        background: #0e1420;
        color: #f0f4ff;
        border: 1px solid rgba(255,255,255,0.12);
        border-radius: 8px;
        padding: 10px 14px;
        font-size: 12px;
        font-family: system-ui, sans-serif;
        max-width: 300px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.6);
        pointer-events: none;
        line-height: 1.6;
        display: none;
      }
      #nsx-tooltip.risk-high   { border-left: 3px solid #ef4444; }
      #nsx-tooltip.risk-medium { border-left: 3px solid #f59e0b; }
      #nsx-tooltip.risk-low    { border-left: 3px solid #10b981; }

      /* Email banner */
      .nsx-email-banner {
        display: flex !important;
        align-items: center;
        gap: 10px;
        padding: 9px 16px;
        font-family: system-ui, 'Inter', sans-serif;
        font-size: 12px;
        font-weight: 600;
        line-height: 1.4;
        cursor: pointer;
        z-index: 9999;
        flex-wrap: wrap;
        animation: nsx-slide-down 0.3s ease;
        border-radius: 6px;
        margin: 4px 8px;
      }
      @keyframes nsx-slide-down {
        from { opacity: 0; transform: translateY(-8px); }
        to   { opacity: 1; transform: translateY(0); }
      }
      .nsx-banner-high   { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
      .nsx-banner-medium { background: #451a03; color: #fed7aa; border: 1px solid #7c2d12; }
      .nsx-banner-low    { background: #052e16; color: #bbf7d0; border: 1px solid #14532d; }
      .nsx-banner-dismiss { margin-left: auto; opacity: 0.6; font-size: 14px; cursor: pointer; padding: 0 4px; }
      .nsx-banner-dismiss:hover { opacity: 1; }

      /* Offline indicator */
      .nsx-offline-tag { background: #374151; color: #9ca3af; font-size: 9px; border-radius: 3px; padding: 0 4px; margin-left: 2px; }
    `;
    document.head.appendChild(s);
  }

  // ─── Tooltip ──────────────────────────────────────────────────────────────
  let tooltipEl = null;
  function getTooltip() {
    if (!tooltipEl) {
      tooltipEl = document.createElement("div");
      tooltipEl.id = "nsx-tooltip";
      document.body.appendChild(tooltipEl);
    }
    return tooltipEl;
  }
  function showTooltip(html, risk, x, y) {
    const t = getTooltip();
    t.className = `risk-${(risk || "low").toLowerCase()}`;
    t.innerHTML = html;
    t.style.display = "block";
    t.style.left = `${Math.min(x + 14, window.innerWidth - 320)}px`;
    t.style.top  = `${Math.max(y - 8, 4)}px`;
  }
  function hideTooltip() { if (tooltipEl) tooltipEl.style.display = "none"; }

  // ─── URL helpers ──────────────────────────────────────────────────────────
  function isExternal(href) {
    try {
      const u = new URL(href, location.href);
      return u.protocol.startsWith("http") && u.hostname !== location.hostname;
    } catch { return false; }
  }

  // ─── Server availability check ────────────────────────────────────────────
  let serverAvailable = null;
  async function checkServer() {
    try {
      const r = await fetch("http://127.0.0.1:5000/api/logs", { method: "GET", signal: AbortSignal.timeout(2000) });
      serverAvailable = r.ok;
    } catch { serverAvailable = false; }
    return serverAvailable;
  }

  // ─── Scan URL (server first, local fallback) ──────────────────────────────
  const urlCache = new Map();
  async function scanUrl(url) {
    if (urlCache.has(url)) return urlCache.get(url);

    // Try server first
    if (serverAvailable !== false) {
      try {
        const r = await chrome.runtime.sendMessage({ type: "NSX_SCAN_URL", url });
        if (r?.ok) {
          urlCache.set(url, r.result);
          return r.result;
        }
      } catch { serverAvailable = false; }
    }

    // Local fallback
    const result = localScanUrl(url);
    result.source = "local";
    urlCache.set(url, result);
    return result;
  }

  // ─── Annotate a link element ──────────────────────────────────────────────
  function annotateLinkElement(anchor, result) {
    // Remove old badge
    anchor.querySelectorAll("." + NSX_BADGE_CLASS).forEach(b => b.remove());

    const risk = result.risk_level || result.risk || "LOW";
    const badgeClass = `nsx-badge-${risk.toLowerCase()}`;
    const label = risk === "HIGH" ? "⚠ UNSAFE" : risk === "MEDIUM" ? "⚠ WARN" : "✓ OK";

    const badge = document.createElement("span");
    badge.className = `${NSX_BADGE_CLASS} ${badgeClass}`;
    badge.textContent = label;
    if (result.source === "local") {
      const offTag = document.createElement("span");
      offTag.className = "nsx-offline-tag";
      offTag.textContent = "local";
      badge.appendChild(offTag);
    }

    anchor.appendChild(badge);

    // Build tooltip
    const domain = result.domain || url;
    const patterns = result.suspicious_patterns || result.findings || [];
    const lines = [
      `<strong>🛡️ NetSecureX</strong> <span style="opacity:.6;font-size:10px">${result.source === "local" ? "local scan" : "Safe Browsing"}</span>`,
      `<code style="color:#93c5fd;font-size:11px">${domain}</code>`,
      `Risk: <strong style="color:${risk === "HIGH" ? "#fca5a5" : risk === "MEDIUM" ? "#fde68a" : "#6ee7b7"}">${risk}</strong>`,
    ];
    if (result.threat_type)    lines.push(`Threat: ${result.threat_type}`);
    if (patterns.length)       lines.push(`⚠ ${patterns[0]}`);
    if (result.details && !result.is_malicious) lines.push(`<span style="opacity:.7">${result.details}</span>`);
    const tipHTML = lines.join("<br>");

    badge.addEventListener("mouseenter", e => showTooltip(tipHTML, risk, e.clientX, e.clientY));
    badge.addEventListener("mousemove",  e => showTooltip(tipHTML, risk, e.clientX, e.clientY));
    badge.addEventListener("mouseleave", hideTooltip);
  }

  // ─── Batch link scanner ───────────────────────────────────────────────────
  let highestRisk = "LOW";
  const RISK_ORD = { LOW: 0, MEDIUM: 1, HIGH: 2 };

  function updateHighestRisk(risk) {
    if (RISK_ORD[risk] > RISK_ORD[highestRisk]) {
      highestRisk = risk;
      chrome.runtime.sendMessage({ type: "NSX_PAGE_RISK", risk_level: highestRisk }).catch(() => {});
    }
  }

  async function scanLinks() {
    const anchors = Array.from(document.querySelectorAll(`a[href]:not([${NSX_ATTR}])`))
      .filter(a => isExternal(a.href))
      .slice(0, MAX_LINKS_PER_PAGE);

    if (!anchors.length) return;

    // Mark all as pending immediately
    anchors.forEach(a => {
      a.setAttribute(NSX_ATTR, "pending");
      a.querySelectorAll("." + NSX_BADGE_CLASS).forEach(b => b.remove());
      const badge = document.createElement("span");
      badge.className = `${NSX_BADGE_CLASS} nsx-badge-scan`;
      badge.textContent = "…";
      a.appendChild(badge);
    });

    // Process in batches
    for (let i = 0; i < anchors.length; i += SCAN_BATCH_SIZE) {
      const batch = anchors.slice(i, i + SCAN_BATCH_SIZE);
      await Promise.allSettled(batch.map(async anchor => {
        try {
          const result = await scanUrl(anchor.href);
          const risk = result.risk_level || result.risk || "LOW";
          anchor.setAttribute(NSX_ATTR, risk);
          annotateLinkElement(anchor, result);
          updateHighestRisk(risk);
        } catch {
          anchor.setAttribute(NSX_ATTR, "error");
          anchor.querySelectorAll("." + NSX_BADGE_CLASS).forEach(b => b.remove());
        }
      }));
    }
  }

  // ─── Webmail Detection ────────────────────────────────────────────────────
  const isGmail   = () => location.hostname === "mail.google.com";
  const isOutlook = () => /outlook\.|office\.com/.test(location.hostname);

  let lastEmailKey = "";

  function extractGmailEmail() {
    try {
      // Multiple selectors for Gmail's evolving DOM
      const subjectEl = document.querySelector('.hP, [data-thread-perm-id] .bog, h2.hP');
      const fromEl    = document.querySelector('.gD[email], .go .gD');
      const bodyEl    = document.querySelector('.a3s.aiL, .ii.gt .a3s');

      const subject     = subjectEl?.textContent?.trim() || "";
      const fromAddress = fromEl?.getAttribute("email") || fromEl?.dataset?.hovercard_id || "";
      const displayName = fromEl?.getAttribute("name") || fromEl?.textContent?.trim() || "";
      const bodyText    = bodyEl?.innerText?.trim() || "";
      const urls        = Array.from(bodyEl?.querySelectorAll("a[href]") || [])
                               .map(a => a.href).filter(h => h.startsWith("http"));

      if (!subject && !fromAddress) return null;

      const key = `${subject}|${fromAddress}`;
      if (key === lastEmailKey) return null;
      lastEmailKey = key;

      return { display_name: displayName, from_address: fromAddress, subject, body: bodyText, urls };
    } catch { return null; }
  }

  function extractOutlookEmail() {
    try {
      // Outlook Web selectors (multiple versions)
      const subjectEl = document.querySelector(
        '[class*="SubjectLine"], [class*="subject-text"], [aria-label*="Subject"], .allowTextSelection [role="heading"]'
      );
      const fromEl = document.querySelector(
        '[class*="SenderName"], [class*="sender"], [aria-label*="From"] span, .ms-Persona-primaryText'
      );
      const bodyEl = document.querySelector(
        '[class*="ReadingPane"] [class*="body"], .allowTextSelection, [id*="UniqueMessageBody"]'
      );

      const subject     = subjectEl?.textContent?.trim() || "";
      const fromAddress = fromEl?.textContent?.trim() || "";
      const bodyText    = bodyEl?.innerText?.trim() || "";
      const urls        = Array.from(bodyEl?.querySelectorAll("a[href]") || [])
                               .map(a => a.href).filter(h => h.startsWith("http"));

      if (!subject && !fromAddress) return null;

      const key = `${subject}|${fromAddress}`;
      if (key === lastEmailKey) return null;
      lastEmailKey = key;

      return { display_name: fromAddress, from_address: "", subject, body: bodyText, urls };
    } catch { return null; }
  }

  // ─── Email Scan & Banner ──────────────────────────────────────────────────
  let currentBanner = null;

  async function scanCurrentEmail() {
    let payload = null;
    if (isGmail())   payload = extractGmailEmail();
    else if (isOutlook()) payload = extractOutlookEmail();
    if (!payload) return;

    let result;

    // Try server first, fall back to local
    if (serverAvailable !== false) {
      try {
        const resp = await chrome.runtime.sendMessage({ type: "NSX_SCAN_EMAIL", payload });
        if (resp?.ok) result = resp.result;
        else result = localScanEmail(payload);
      } catch { result = localScanEmail(payload); }
    } else {
      result = localScanEmail(payload);
    }

    renderEmailBanner(result, payload);
    updateHighestRisk(result.risk_level);
  }

  function renderEmailBanner(result, payload) {
    if (currentBanner) { currentBanner.remove(); currentBanner = null; }

    const risk = result.risk_level;
    const emoji = { HIGH: "🔴", MEDIUM: "🟡", LOW: "🟢" }[risk] || "🟢";
    const bannerClass = `nsx-banner-${risk.toLowerCase()}`;

    const flags = [];
    if (result.urgency_detected)     flags.push("⚡ Urgency");
    if (result.display_name_spoofed) flags.push("🎭 Spoof");
    if (result.lookalike_detected)   flags.push("🔗 Lookalike");
    if (result.url_results?.some(u => u.is_malicious || u.risk === "HIGH")) flags.push("☠️ Bad URL");
    const isLocal = result.source === "local";

    currentBanner = document.createElement("div");
    currentBanner.className = `nsx-email-banner ${bannerClass}`;
    currentBanner.setAttribute("role", "alert");
    currentBanner.innerHTML = `
      <span style="font-size:15px">${emoji}</span>
      <span><strong>NetSecureX ${risk} RISK</strong> · Score: ${result.total_score}/100${isLocal ? ' <span style="font-size:9px;opacity:.6">(local)</span>' : ''}</span>
      ${flags.length ? `<span style="font-weight:400;opacity:.85">${flags.join(" · ")}</span>` : ""}
      ${result.reasons?.[0] ? `<span style="opacity:.65;font-size:11px;font-weight:400">${result.reasons[0].slice(0, 70)}</span>` : ""}
      <span class="nsx-banner-dismiss" title="Dismiss">✕</span>
    `;

    currentBanner.querySelector(".nsx-banner-dismiss").onclick = (e) => {
      e.stopPropagation();
      currentBanner?.remove();
      currentBanner = null;
    };

    // Insert at top of email pane
    const target = isGmail()
      ? document.querySelector('.nH.aHU, .adP.adO, [role="main"]')
      : document.querySelector('[class*="ReadingPane"], [class*="readingPane"]') || document.body;

    if (target) {
      target.insertBefore(currentBanner, target.firstChild);
    } else {
      document.body.insertBefore(currentBanner, document.body.firstChild);
    }
  }

  // ─── SPA Navigation detection (Gmail/Outlook use History API) ────────────
  let lastUrl = location.href;
  function checkUrlChange() {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      lastEmailKey = "";  // Reset email key on navigation
      if (currentBanner) { currentBanner.remove(); currentBanner = null; }
      scheduleEmailScan();
      scheduleLinkScan();
    }
  }

  // ─── Debounced Schedulers ─────────────────────────────────────────────────
  let linkTimer = null, emailTimer = null, urlTimer = null;

  function scheduleLinkScan() {
    clearTimeout(linkTimer);
    linkTimer = setTimeout(scanLinks, SCAN_DELAY_MS);
  }

  function scheduleEmailScan() {
    clearTimeout(emailTimer);
    emailTimer = setTimeout(scanCurrentEmail, EMAIL_SCAN_DELAY);
  }

  function scheduleUrlCheck() {
    clearTimeout(urlTimer);
    urlTimer = setTimeout(checkUrlChange, 300);
  }

  // ─── DOM MutationObserver ─────────────────────────────────────────────────
  const observer = new MutationObserver(() => {
    scheduleLinkScan();
    scheduleUrlCheck();
    if (isGmail() || isOutlook()) scheduleEmailScan();
  });

  // ─── Re-scan event (triggered from popup) ─────────────────────────────────
  document.addEventListener("nsx-rescan", () => {
    // Clear scanned state to force re-scan
    document.querySelectorAll(`[${NSX_ATTR}]`).forEach(el => el.removeAttribute(NSX_ATTR));
    urlCache.clear();
    highestRisk = "LOW";
    scanLinks();
  });

  // ─── Init ─────────────────────────────────────────────────────────────────
  async function init() {
    injectStyles();
    await checkServer();  // Warm-up server check
    scheduleLinkScan();
    if (isGmail() || isOutlook()) scheduleEmailScan();

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
      characterData: false,
    });

    // Poll for SPA URL changes every 1.5s as fallback (History API isn't always catchable)
    setInterval(checkUrlChange, 1500);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
