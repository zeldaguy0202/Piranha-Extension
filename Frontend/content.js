const PIRANHA_DEFAULT_API = "http://127.0.0.1:8000";
const PIRANHA_SCAN_TIMEOUT_MS = 7000;

function getSettings() {
  return new Promise((resolve) => chrome.storage.sync.get(["blockedSites", "apiUrl", "automaticScanning", "passwordDetection"], resolve));
}

function setSettings(value) {
  return new Promise((resolve) => chrome.storage.sync.set(value, resolve));
}

function hostnameIsBlocked(hostname, blockedSites) {
  const clean = hostname.replace(/^www\./, "").toLowerCase();
  return blockedSites.some((blocked) => clean === blocked || clean.endsWith(`.${blocked}`));
}

function escapeText(value) {
  return String(value).replace(/[&<>"']/g, "");
}

function leavePage() {
  if (history.length > 1) history.back();
  else window.location.replace("about:blank");
}

function showPersonalBlockPage(hostname) {
  document.documentElement.style.visibility = "visible";
  document.documentElement.innerHTML = `
    <head><title>Blocked by Piranha</title></head>
    <body style="margin:0;background:#121212;color:white;font-family:system-ui;display:grid;place-items:center;min-height:100vh">
      <main style="max-width:560px;text-align:center;padding:32px">
        <h1 style="color:#ff3e3e">Blocked by Piranha</h1>
        <p><strong>${escapeText(hostname)}</strong> is on your personal block list.</p>
        <p style="color:#aaa">Remove it from the extension popup if you want to visit it.</p>
        <button id="piranha-back" style="padding:12px 22px;border:0;border-radius:8px;background:#ff3e3e;color:white;font-weight:700;cursor:pointer">Go back</button>
      </main>
    </body>`;
  document.getElementById("piranha-back").addEventListener("click", leavePage);
  window.stop();
}

function showThreatWarning(result) {
  document.documentElement.style.visibility = "visible";
  const malicious = result.verdict === "malicious";
  const color = malicious ? "#ff3e3e" : "#e3a008";
  const title = malicious ? "Malicious link warning" : "Suspicious link warning";
  const explanation = malicious
    ? "Piranha found high-confidence malicious-link evidence for this address."
    : "Piranha found suspicious characteristics. This is not proof that the page is malicious, but you should verify the address before continuing.";
  const evidence = result.evidence.length
    ? result.evidence.slice(0, 5).map((item) => `<li style="margin:8px 0"><strong>${escapeText(item.source)}:</strong> ${escapeText(item.detail)}</li>`).join("")
    : "<li>No detailed evidence was returned.</li>";

  const host = document.createElement("div");
  host.id = "piranha-threat-warning";
  host.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:#101214;color:#fff;font-family:system-ui,sans-serif;display:grid;place-items:center;padding:24px";
  host.innerHTML = `
    <main style="width:min(680px,100%);background:#1d2125;border:2px solid ${color};border-radius:16px;padding:32px;box-shadow:0 24px 80px rgba(0,0,0,.65)">
      <p style="color:${color};font-size:14px;font-weight:800;letter-spacing:.08em;margin:0 0 8px">PIRANHA LINK GUARD</p>
      <h1 style="color:#fff;font-size:30px;margin:0 0 12px">${title}</h1>
      <p style="font-size:17px;line-height:1.5">${explanation}</p>
      <p style="word-break:break-all;color:#c7c7c7"><strong>Address:</strong> ${escapeText(result.normalized_url)}</p>
      <p><strong>Risk score:</strong> ${result.risk_score}/100</p>
      <ul style="line-height:1.4;padding-left:22px">${evidence}</ul>
      <p style="color:#aeb4ba;font-size:13px">Piranha cannot guarantee that any link is safe. Continuing is your decision.</p>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:22px">
        <button id="piranha-go-back" style="padding:12px 18px;border:0;border-radius:8px;background:${color};color:#fff;font-weight:800;cursor:pointer">Go back</button>
        <button id="piranha-block-site" style="padding:12px 18px;border:1px solid #737b83;border-radius:8px;background:#272c31;color:#fff;font-weight:700;cursor:pointer">Block this site</button>
        <button id="piranha-continue" style="padding:12px 18px;border:0;background:transparent;color:#b8bec5;text-decoration:underline;cursor:pointer">Continue anyway</button>
      </div>
    </main>`;
  document.documentElement.appendChild(host);

  host.querySelector("#piranha-go-back").addEventListener("click", leavePage);
  host.querySelector("#piranha-continue").addEventListener("click", () => host.remove());
  host.querySelector("#piranha-block-site").addEventListener("click", async () => {
    const settings = await getSettings();
    const clean = window.location.hostname.replace(/^www\./, "").toLowerCase();
    const blockedSites = settings.blockedSites || [];
    if (!blockedSites.includes(clean)) blockedSites.push(clean);
    await setSettings({ blockedSites });
    leavePage();
  });
}

async function scanUrl(url, apiUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PIRANHA_SCAN_TIMEOUT_MS);
  try {
    const response = await fetch(`${apiUrl.replace(/\/$/, "")}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function proactivelyScanCurrentPage() {
  const settings = await getSettings();
  if (hostnameIsBlocked(window.location.hostname, settings.blockedSites || [])) {
    showPersonalBlockPage(window.location.hostname);
    return;
  }
  if (settings.automaticScanning === false) return;

  document.documentElement.style.visibility = "hidden";
  try {
    const result = await scanUrl(window.location.href, settings.apiUrl || PIRANHA_DEFAULT_API);
    document.documentElement.style.visibility = "visible";
    if (["malicious", "suspicious"].includes(result.verdict)) showThreatWarning(result);
  } catch (_) {
    // The local API may be offline. Restore the page and allow normal navigation.
    document.documentElement.style.visibility = "visible";
  }
}

proactivelyScanCurrentPage();

const passwordWarnings = new WeakMap();
const checkedPasswordHashes = new WeakMap();

function looksLikeNewPasswordField(input) {
  if (!(input instanceof HTMLInputElement) || input.type !== "password") return false;
  if (input.autocomplete.toLowerCase() === "new-password") return true;
  const identity = `${input.name} ${input.id} ${input.getAttribute("aria-label") || ""}`.toLowerCase();
  if (/new|confirm|create|signup|sign-up|register/.test(identity)) return true;
  return Boolean(input.form && input.form.querySelectorAll('input[type="password"]').length >= 2);
}

async function sha1Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function clearPasswordWarning(input) {
  const warning = passwordWarnings.get(input);
  if (warning) warning.remove();
  passwordWarnings.delete(input);
}

function showPasswordWarning(input, count) {
  clearPasswordWarning(input);
  const warning = document.createElement("div");
  warning.setAttribute("role", "alert");
  warning.style.cssText = "margin:6px 0;padding:10px 12px;border:2px solid #d32f2f;border-radius:8px;background:#fff2f2;color:#8b0000;font:600 14px/1.35 system-ui,sans-serif;position:relative;z-index:2147483646";
  warning.textContent = `Piranha warning: This password appears ${count.toLocaleString()} times in the Have I Been Pwned database. Choose a unique password.`;
  input.insertAdjacentElement("afterend", warning);
  passwordWarnings.set(input, warning);
}

async function checkCompletedPassword(input) {
  const settings = await getSettings();
  if (settings.passwordDetection === false || !looksLikeNewPasswordField(input) || !input.value) return;

  let password = input.value;
  const fullHash = await sha1Hex(password);
  password = "";
  if (checkedPasswordHashes.get(input) === fullHash) return;
  checkedPasswordHashes.set(input, fullHash);

  const prefix = fullHash.slice(0, 5);
  const suffix = fullHash.slice(5);
  try {
    const response = await fetch(`${(settings.apiUrl || PIRANHA_DEFAULT_API).replace(/\/$/, "")}/api/password/range/${prefix}`);
    if (!response.ok) return;
    const result = await response.json();
    if (checkedPasswordHashes.get(input) !== fullHash) return;
    const count = Number(result.matches[suffix] || 0);
    if (count > 0) showPasswordWarning(input, count);
    else clearPasswordWarning(input);
  } catch (_) {
    // Do not interrupt password creation when the local backend or HIBP is unavailable.
  }
}

document.addEventListener("focusout", (event) => {
  if (event.target instanceof HTMLInputElement && event.target.type === "password") {
    checkCompletedPassword(event.target);
  }
}, true);

document.addEventListener("input", (event) => {
  if (event.target instanceof HTMLInputElement && event.target.type === "password") {
    checkedPasswordHashes.delete(event.target);
    clearPasswordWarning(event.target);
  }
}, true);

// Pre-scan ordinary cross-site clicks. Automatic page scanning remains the fallback
// for address-bar navigation, bookmarks, redirects, and links opened by other apps.
document.addEventListener("click", async (event) => {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const anchor = event.target.closest && event.target.closest("a[href]");
  if (!anchor || anchor.hasAttribute("download")) return;
  let destination;
  try { destination = new URL(anchor.href); } catch (_) { return; }
  if (!["http:", "https:"].includes(destination.protocol) || destination.origin === window.location.origin) return;

  event.preventDefault();
  const pendingWindow = anchor.target === "_blank" ? window.open("about:blank", "_blank") : null;
  if (pendingWindow) pendingWindow.opener = null;
  const settings = await getSettings();
  if (hostnameIsBlocked(destination.hostname, settings.blockedSites || [])) {
    if (pendingWindow) pendingWindow.close();
    alert(`Piranha blocked ${destination.hostname} because it is on your personal block list.`);
    return;
  }
  try {
    const result = await scanUrl(destination.href, settings.apiUrl || PIRANHA_DEFAULT_API);
    if (["malicious", "suspicious"].includes(result.verdict)) {
      const proceed = confirm(`Piranha marked this link ${result.verdict} (${result.risk_score}/100). Continue?`);
      if (!proceed) {
        if (pendingWindow) pendingWindow.close();
        return;
      }
    }
  } catch (_) {
    // Fail open when the configured API is unavailable.
  }
  if (pendingWindow) pendingWindow.location.replace(destination.href);
  else window.location.assign(destination.href);
}, true);
