/**
 * NetSecureX Extension — Background Service Worker
 * Handles context menu (right-click → Scan this link), badge updates,
 * and bridges messages between content scripts and popup.
 */

const API_BASE = "http://127.0.0.1:5000";

// ─── Context Menu Setup ────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "nsx-scan-link",
    title: "🛡️ NetSecureX: Scan this link",
    contexts: ["link"],
  });
  chrome.contextMenus.create({
    id: "nsx-scan-selection",
    title: "🛡️ NetSecureX: Scan selected text as URL",
    contexts: ["selection"],
  });
  // Default badge
  chrome.action.setBadgeBackgroundColor({ color: "#3b82f6" });
  chrome.action.setBadgeText({ text: "NSX" });
});

// ─── Context Menu Clicks ───────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let targetUrl = "";
  if (info.menuItemId === "nsx-scan-link" && info.linkUrl) {
    targetUrl = info.linkUrl;
  } else if (info.menuItemId === "nsx-scan-selection" && info.selectionText) {
    targetUrl = info.selectionText.trim();
    // Prepend https:// if no scheme
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = "https://" + targetUrl;
    }
  }

  if (!targetUrl) return;

  try {
    const result = await scanUrl(targetUrl);
    const riskEmoji = result.risk_level === "HIGH" ? "🔴" : result.risk_level === "MEDIUM" ? "🟡" : "🟢";
    const msg = `${riskEmoji} ${result.risk_level} RISK\n${result.domain || targetUrl}\n${result.details || (result.suspicious_patterns || []).join(", ") || "Clean"}`;
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: `NetSecureX — ${result.risk_level} Risk`,
      message: msg,
      priority: result.risk_level === "HIGH" ? 2 : 1,
    });
    // Update badge for the tab
    updateBadgeForTab(tab.id, result.risk_level);
  } catch (err) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "NetSecureX — Connection Error",
      message: "Cannot reach NetSecureX server at 127.0.0.1:5000. Make sure app.py is running.",
      priority: 1,
    });
  }
});

// ─── Message Bridge from Content Script ───────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "NSX_SCAN_URL") {
    scanUrl(msg.url)
      .then(result => sendResponse({ ok: true, result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true; // Keep channel open for async
  }

  if (msg.type === "NSX_SCAN_EMAIL") {
    scanEmail(msg.payload)
      .then(result => sendResponse({ ok: true, result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "NSX_PAGE_RISK") {
    // Content script reports highest risk found on page
    updateBadgeForTab(sender.tab?.id, msg.risk_level);
    return false;
  }
});

// ─── Helpers ───────────────────────────────────────────────────────────────
async function scanUrl(url) {
  const resp = await fetch(`${API_BASE}/api/scan_url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function scanEmail(payload) {
  const resp = await fetch(`${API_BASE}/api/scan_email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

function updateBadgeForTab(tabId, riskLevel) {
  if (!tabId) return;
  const colors = { HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#10b981" };
  const labels = { HIGH: "HIGH", MEDIUM: "MED", LOW: "OK" };
  chrome.action.setBadgeBackgroundColor({ tabId, color: colors[riskLevel] || "#3b82f6" });
  chrome.action.setBadgeText({ tabId, text: labels[riskLevel] || "NSX" });
}
