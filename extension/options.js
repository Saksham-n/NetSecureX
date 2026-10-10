/**
 * NetSecureX Extension — Options Page Script
 */

const DEFAULTS = {
  serverUrl:    "http://127.0.0.1:5000",
  scanLinks:    true,
  scanEmail:    true,
  localFallback: true,
  notifications: true,
};

function showStatus(msg, isOk) {
  const el = document.getElementById("status-msg");
  el.textContent = msg;
  el.className = `status-msg show ${isOk ? "status-ok" : "status-err"}`;
  setTimeout(() => el.classList.remove("show"), 4000);
}

async function loadSettings() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  document.getElementById("server-url").value  = s.serverUrl;
  document.getElementById("tog-links").checked = s.scanLinks;
  document.getElementById("tog-email").checked = s.scanEmail;
  document.getElementById("tog-local").checked = s.localFallback;
  document.getElementById("tog-notif").checked = s.notifications;
}

document.getElementById("btn-save").addEventListener("click", async () => {
  const settings = {
    serverUrl:     document.getElementById("server-url").value.trim() || DEFAULTS.serverUrl,
    scanLinks:     document.getElementById("tog-links").checked,
    scanEmail:     document.getElementById("tog-email").checked,
    localFallback: document.getElementById("tog-local").checked,
    notifications: document.getElementById("tog-notif").checked,
  };
  await chrome.storage.sync.set(settings);
  showStatus("✅ Settings saved!", true);
});

document.getElementById("btn-test").addEventListener("click", async () => {
  const url = document.getElementById("server-url").value.trim() || DEFAULTS.serverUrl;
  try {
    const resp = await fetch(`${url}/api/logs`, { signal: AbortSignal.timeout(3000) });
    if (resp.ok) {
      showStatus(`✅ Connected to NetSecureX at ${url}`, true);
    } else {
      showStatus(`⚠️ Server responded with HTTP ${resp.status}`, false);
    }
  } catch (err) {
    showStatus(`❌ Cannot connect to ${url} — make sure app.py is running`, false);
  }
});

loadSettings();
