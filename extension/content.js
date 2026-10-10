/**
 * NetSecureX Extension — Content Script
 * Injected into every page to:
 *   1. Scan all hyperlinks and annotate suspicious/malicious ones with visual badges
 *   2. Detect webmail contexts (Gmail / Outlook) and auto-extract email fields for scanning
 *   3. Report the page's highest risk level back to the background worker (badge update)
 *
 * Design: non-blocking, batched scanning with debouncing on DOM mutations.
 */

(function () {
  "use strict";

  const NSX_ATTR = "data-nsx-scanned";
  const NSX_BADGE_CLASS = "nsx-link-badge";
  const API_BASE = "http://127.0.0.1:5000";

  // ─── Inject Stylesheet ─────────────────────────────────────────────────
  function injectStyles() {
    if (document.getElementById("nsx-content-styles")) return;
    const style = document.createElement("style");
    style.id = "nsx-content-styles";
    style.textContent = `
      .nsx-link-badge {
        display: inline-block;
        font-size: 10px;
        font-weight: 700;
        font-family: 'Inter', system-ui, sans-serif;
        border-radius: 4px;
        padding: 1px 5px;
        margin-left: 4px;
        vertical-align: middle;
        cursor: default;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        line-height: 16px;
        animation: nsx-pop 0.2s ease;
      }
      @keyframes nsx-pop {
        0% { transform: scale(0.7); opacity: 0; }
        100% { transform: scale(1); opacity: 1; }
      }
      .nsx-badge-high   { background: #ef4444; color: #fff; }
      .nsx-badge-medium { background: #f59e0b; color: #000; }
      .nsx-badge-low    { background: #10b981; color: #fff; }
      .nsx-badge-scan   { background: #3b82f6; color: #fff; }

      .nsx-tooltip {
        position: fixed;
        z-index: 2147483647;
        background: #111827;
        color: #f3f4f6;
        border: 1px solid rgba(255,255,255,0.12);
        border-radius: 8px;
        padding: 10px 14px;
        font-size: 12px;
        font-family: 'Inter', system-ui, sans-serif;
        max-width: 320px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        pointer-events: none;
        line-height: 1.6;
      }
      .nsx-tooltip-high   { border-left: 3px solid #ef4444; }
      .nsx-tooltip-medium { border-left: 3px solid #f59e0b; }
      .nsx-tooltip-low    { border-left: 3px solid #10b981; }

      .nsx-email-banner {
        position: sticky;
        top: 0;
        z-index: 99999;
        padding: 10px 20px;
        font-family: 'Inter', system-ui, sans-serif;
        font-size: 13px;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 10px;
        animation: nsx-slide-down 0.3s ease;
        cursor: pointer;
      }
      @keyframes nsx-slide-down {
        from { transform: translateY(-100%); opacity: 0; }
        to   { transform: translateY(0);     opacity: 1; }
      }
      .nsx-banner-high   { background: #7f1d1d; color: #fca5a5; border-bottom: 2px solid #ef4444; }
      .nsx-banner-medium { background: #78350f; color: #fde68a; border-bottom: 2px solid #f59e0b; }
      .nsx-banner-low    { background: #064e3b; color: #6ee7b7; border-bottom: 2px solid #10b981; }
    `;
    document.head.appendChild(style);
  }

  // ─── Tooltip ───────────────────────────────────────────────────────────
  let tooltip = null;
  function showTooltip(text, riskLevel, x, y) {
    if (!tooltip) {
      tooltip = document.createElement("div");
      tooltip.className = "nsx-tooltip";
      document.body.appendChild(tooltip);
    }
    tooltip.className = `nsx-tooltip nsx-tooltip-${riskLevel.toLowerCase()}`;
    tooltip.innerHTML = text;
    tooltip.style.display = "block";
    tooltip.style.left = `${Math.min(x + 12, window.innerWidth - 340)}px`;
    tooltip.style.top = `${Math.max(y - 10, 0)}px`;
  }
  function hideTooltip() {
    if (tooltip) tooltip.style.display = "none";
  }

  // ─── URL Helpers ───────────────────────────────────────────────────────
  function isExternalLink(href) {
    try {
      const u = new URL(href, location.href);
      return u.hostname !== location.hostname && u.protocol.startsWith("http");
    } catch { return false; }
  }

  function extractLinksFromPage() {
    return Array.from(document.querySelectorAll("a[href]"))
      .map(a => a.href)
      .filter(href => isExternalLink(href));
  }

  // ─── Link Annotation ──────────────────────────────────────────────────
  async function annotateLinkElement(anchor, result) {
    const risk = result.risk_level;
    const badgeClass = `nsx-badge-${risk.toLowerCase()}`;
    const existingBadge = anchor.querySelector("." + NSX_BADGE_CLASS);
    if (existingBadge) existingBadge.remove();

    const badge = document.createElement("span");
    badge.className = `${NSX_BADGE_CLASS} ${badgeClass}`;
    badge.textContent = risk === "HIGH" ? "⚠ UNSAFE" : risk === "MEDIUM" ? "⚠ WARN" : "✓ OK";
    badge.title = result.details || (result.suspicious_patterns || []).join(", ") || "Clean";
    anchor.appendChild(badge);

    // Tooltip on hover
    const tooltipLines = [`<strong>🛡️ NetSecureX Scan</strong><br><code style="color:#93c5fd">${result.domain || result.url}</code><br>Risk: <strong>${risk}</strong>`];
    if (result.threat_type) tooltipLines.push(`Threat: ${result.threat_type}`);
    if (result.suspicious_patterns?.length) tooltipLines.push(`Patterns: ${result.suspicious_patterns.join(", ")}`);
    if (result.details) tooltipLines.push(`Detail: ${result.details}`);
    const tipHTML = tooltipLines.join("<br>");

    badge.addEventListener("mouseenter", (e) => showTooltip(tipHTML, risk, e.clientX, e.clientY));
    badge.addEventListener("mousemove", (e) => showTooltip(tipHTML, risk, e.clientX, e.clientY));
    badge.addEventListener("mouseleave", hideTooltip);
  }

  // ─── Batch URL Scan ────────────────────────────────────────────────────
  let scannedUrls = new Set();
  let highestRisk = "LOW";

  const RISK_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2 };
  function updateHighestRisk(risk) {
    if (RISK_ORDER[risk] > RISK_ORDER[highestRisk]) {
      highestRisk = risk;
      chrome.runtime.sendMessage({ type: "NSX_PAGE_RISK", risk_level: highestRisk });
    }
  }

  async function scanLinkBatch(anchors) {
    // Filter unscanned external links
    const toScan = anchors.filter(a => !a.hasAttribute(NSX_ATTR) && isExternalLink(a.href));
    if (!toScan.length) return;

    // Mark as scanning
    toScan.forEach(a => {
      a.setAttribute(NSX_ATTR, "pending");
      const badge = document.createElement("span");
      badge.className = `${NSX_BADGE_CLASS} nsx-badge-scan`;
      badge.textContent = "…";
      a.appendChild(badge);
    });

    // Scan each (could batch but keeping per-link for accuracy)
    for (const anchor of toScan) {
      if (scannedUrls.has(anchor.href)) {
        anchor.setAttribute(NSX_ATTR, "cached");
        continue;
      }
      scannedUrls.add(anchor.href);
      try {
        const result = await chrome.runtime.sendMessage({ type: "NSX_SCAN_URL", url: anchor.href });
        if (result?.ok) {
          anchor.setAttribute(NSX_ATTR, result.result.risk_level);
          await annotateLinkElement(anchor, result.result);
          updateHighestRisk(result.result.risk_level);
        } else {
          anchor.setAttribute(NSX_ATTR, "error");
        }
      } catch (err) {
        anchor.setAttribute(NSX_ATTR, "error");
      }
    }
  }

  // ─── Webmail Detection: Gmail ──────────────────────────────────────────
  function isGmail() { return location.hostname === "mail.google.com"; }
  function isOutlook() { return location.hostname.includes("outlook") || location.hostname.includes("office.com"); }

  let lastEmailId = null;

  function extractGmailEmail() {
    try {
      // Gmail open email container
      const emailPane = document.querySelector('[data-message-id], .nH.aHU');
      if (!emailPane) return null;

      const subjectEl = document.querySelector('.hP');
      const fromEl = document.querySelector('.gD');
      const bodyEl = document.querySelector('.a3s.aiL');

      const subject = subjectEl?.textContent?.trim() || "";
      const fromRaw = fromEl?.getAttribute("email") || fromEl?.textContent?.trim() || "";
      const displayName = fromEl?.getAttribute("name") || "";
      const bodyText = bodyEl?.innerText?.trim() || "";

      // Extract links from email body
      const links = Array.from(bodyEl?.querySelectorAll("a[href]") || [])
        .map(a => a.href)
        .filter(h => h.startsWith("http"));

      const id = `${subject}|${fromRaw}`;
      if (id === lastEmailId) return null;
      lastEmailId = id;

      return { display_name: displayName, from_address: fromRaw, subject, body: bodyText, urls: links };
    } catch { return null; }
  }

  function extractOutlookEmail() {
    try {
      const subjectEl = document.querySelector('[class*="SubjectLine"], [class*="subject"]');
      const fromEl = document.querySelector('[class*="SenderName"], [class*="sender"]');
      const bodyEl = document.querySelector('[class*="ReadingPane"] [class*="body"], .allowTextSelection');

      const subject = subjectEl?.textContent?.trim() || "";
      const fromRaw = fromEl?.textContent?.trim() || "";
      const bodyText = bodyEl?.innerText?.trim() || "";
      const links = Array.from(bodyEl?.querySelectorAll("a[href]") || [])
        .map(a => a.href)
        .filter(h => h.startsWith("http"));

      const id = `${subject}|${fromRaw}`;
      if (id === lastEmailId) return null;
      lastEmailId = id;

      return { display_name: fromRaw, from_address: "", subject, body: bodyText, urls: links };
    } catch { return null; }
  }

  // ─── Email Scan & Banner ───────────────────────────────────────────────
  let emailBanner = null;
  let emailScanDebounce = null;

  async function scanCurrentEmail() {
    let payload = null;
    if (isGmail()) payload = extractGmailEmail();
    else if (isOutlook()) payload = extractOutlookEmail();
    if (!payload) return;

    try {
      const result = await chrome.runtime.sendMessage({ type: "NSX_SCAN_EMAIL", payload });
      if (!result?.ok) return;
      displayEmailBanner(result.result);
      updateHighestRisk(result.result.risk_level);
    } catch (err) {
      // Server not running — silent fail
    }
  }

  function displayEmailBanner(scanResult) {
    const { risk_level, total_score, reasons, urgency_detected, display_name_spoofed, lookalike_detected } = scanResult;

    // Remove old banner
    if (emailBanner) emailBanner.remove();

    const riskEmoji = risk_level === "HIGH" ? "🔴" : risk_level === "MEDIUM" ? "🟡" : "🟢";
    const bannerClass = `nsx-banner-${risk_level.toLowerCase()}`;

    const flags = [];
    if (urgency_detected) flags.push("⚡ Urgency Language");
    if (display_name_spoofed) flags.push("🎭 Display Name Spoofing");
    if (lookalike_detected) flags.push("🔗 Lookalike Domain");
    if (scanResult.url_results?.some(u => u.is_malicious)) flags.push("☠️ Malicious URL");

    const flagText = flags.length ? flags.join("  ·  ") : "No threats detected";
    const summaryText = reasons?.length ? reasons[0] : "Scanned by NetSecureX";

    emailBanner = document.createElement("div");
    emailBanner.className = `nsx-email-banner ${bannerClass}`;
    emailBanner.innerHTML = `
      <span style="font-size:16px">${riskEmoji}</span>
      <span><strong>NetSecureX ${risk_level} RISK</strong> (Score: ${total_score}/100)</span>
      <span style="font-weight:400;opacity:0.9;margin-left:8px">${flagText}</span>
      <span style="margin-left:auto;font-size:10px;opacity:0.7">${summaryText.slice(0, 80)}</span>
    `;
    emailBanner.title = reasons?.join("\n") || "NetSecureX Email Scan";
    emailBanner.onclick = () => emailBanner.remove();

    // Insert banner into the email view area
    const insertTarget = isGmail()
      ? document.querySelector('.nH.aHU, .adn.ads') || document.body
      : document.querySelector('[class*="ReadingPane"]') || document.body;

    if (insertTarget.firstChild) {
      insertTarget.insertBefore(emailBanner, insertTarget.firstChild);
    } else {
      insertTarget.appendChild(emailBanner);
    }
  }

  // ─── MutationObserver — DOM watcher ───────────────────────────────────
  let linkScanTimeout = null;
  let emailScanTimeout = null;

  function schedulePageScan() {
    clearTimeout(linkScanTimeout);
    linkScanTimeout = setTimeout(() => {
      const anchors = Array.from(document.querySelectorAll("a[href]"));
      scanLinkBatch(anchors);
    }, 800);
  }

  function scheduleEmailScan() {
    clearTimeout(emailScanTimeout);
    emailScanTimeout = setTimeout(scanCurrentEmail, 1200);
  }

  const observer = new MutationObserver(() => {
    schedulePageScan();
    if (isGmail() || isOutlook()) scheduleEmailScan();
  });

  // ─── Init ───────────────────────────────────────────────────────────────
  function init() {
    injectStyles();
    schedulePageScan();
    if (isGmail() || isOutlook()) scheduleEmailScan();
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
