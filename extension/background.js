/**
 * NetSecureX Extension — Background Service Worker (v2)
 * Handles context menu, badge updates, API calls with storage-based server URL,
 * and desktop notifications.
 */

const DEFAULT_SERVER = "http://127.0.0.1:5000";

async function getSettings() {
  return chrome.storage.sync.get({
    serverUrl: DEFAULT_SERVER,
    notifications: true,
    scanLinks: true,
    scanEmail: true,
    localFallback: true,
  });
}

async function getServerUrl() {
  const s = await getSettings();
  return (s.serverUrl || DEFAULT_SERVER).replace(/\/$/, "");
}

// ─── Context Menu Setup ────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "nsx-scan-link",
      title: "🛡️ Scan this link (NetSecureX)",
      contexts: ["link"],
    });
    chrome.contextMenus.create({
      id: "nsx-scan-selection",
      title: "🛡️ Scan selected text as URL (NetSecureX)",
      contexts: ["selection"],
    });
    chrome.contextMenus.create({
      id: "nsx-separator",
      type: "separator",
      contexts: ["link", "selection"],
    });
    chrome.contextMenus.create({
      id: "nsx-open-settings",
      title: "⚙️ NetSecureX Settings",
      contexts: ["action"],
    });
  });

  // Default badge
  chrome.action.setBadgeBackgroundColor({ color: "#3b82f6" });
  chrome.action.setBadgeText({ text: "NSX" });
});

// ─── Context Menu Clicks ───────────────────────────────────────────────────
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "nsx-open-settings") {
    chrome.runtime.openOptionsPage();
    return;
  }

  let targetUrl = "";
  if (info.menuItemId === "nsx-scan-link" && info.linkUrl) {
    targetUrl = info.linkUrl;
  } else if (info.menuItemId === "nsx-scan-selection" && info.selectionText) {
    targetUrl = info.selectionText.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = "https://" + targetUrl;
    }
  }
  if (!targetUrl) return;

  const settings = await getSettings();

  try {
    const result = await scanUrl(targetUrl);
    const riskColors = { HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#10b981" };
    const riskEmoji  = { HIGH: "🔴",      MEDIUM: "🟡",      LOW: "🟢" };
    const risk = result.risk_level || result.risk || "LOW";

    if (settings.notifications) {
      const details = result.details ||
        (result.suspicious_patterns?.join(", ")) ||
        (result.findings?.join(", ")) ||
        "No threats detected";

      chrome.notifications.create(`nsx-${Date.now()}`, {
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: `NetSecureX — ${risk} Risk`,
        message: `${riskEmoji[risk]} ${result.domain || targetUrl}\n${details.slice(0, 120)}`,
        priority: risk === "HIGH" ? 2 : 1,
      });
    }

    updateBadge(tab.id, risk);
  } catch (err) {
    if (settings.notifications) {
      chrome.notifications.create(`nsx-err-${Date.now()}`, {
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: "NetSecureX — Connection Error",
        message: `Cannot reach server. Check Settings or ensure app.py is running.\nError: ${err.message}`,
        priority: 1,
      });
    }
  }
});

// ─── Message Bridge from Content Script / Popup ────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "NSX_SCAN_URL") {
    scanUrl(msg.url)
      .then(result => sendResponse({ ok: true, result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "NSX_SCAN_EMAIL") {
    scanEmail(msg.payload)
      .then(result => sendResponse({ ok: true, result }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "NSX_PAGE_RISK") {
    updateBadge(sender.tab?.id, msg.risk_level);
    return false;
  }

  if (msg.type === "NSX_GET_SETTINGS") {
    getSettings().then(s => sendResponse(s));
    return true;
  }
});

// ─── API Calls ─────────────────────────────────────────────────────────────
async function scanUrl(url) {
  const base = await getServerUrl();
  const resp = await fetch(`${base}/api/scan_url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(5000),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

async function scanEmail(payload) {
  const base = await getServerUrl();
  const resp = await fetch(`${base}/api/scan_email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(8000),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

// ─── Badge ─────────────────────────────────────────────────────────────────
function updateBadge(tabId, riskLevel) {
  if (!tabId) return;
  const colors = { HIGH: "#ef4444", MEDIUM: "#f59e0b", LOW: "#10b981" };
  const labels = { HIGH: "HIGH",    MEDIUM: "MED",      LOW: "OK" };
  chrome.action.setBadgeBackgroundColor({ tabId, color: colors[riskLevel] || "#3b82f6" });
  chrome.action.setBadgeText({ tabId, text: labels[riskLevel] || "NSX" });
}
