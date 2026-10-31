const DEFAULT_API = "http://127.0.0.1:8000";
let currentTabUrl = "";
const $ = (selector) => document.querySelector(selector);
const storageGet = (keys) => new Promise((resolve) => chrome.storage.sync.get(keys, resolve));
const storageSet = (value) => new Promise((resolve) => chrome.storage.sync.set(value, resolve));

async function apiBase() { const data = await storageGet(["apiUrl"]); return (data.apiUrl || DEFAULT_API).replace(/\/$/, ""); }
async function apiRequest(path, options = {}) {
  const response = await fetch(`${await apiBase()}${path}`, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}
function validWebUrl(value) { try { const parsed = new URL(value.includes("://") ? value : `https://${value}`); return ["http:", "https:"].includes(parsed.protocol) ? parsed : null; } catch (_) { return null; } }
function hostnameFrom(value) { const parsed = validWebUrl(value); return parsed ? parsed.hostname.replace(/^www\./, "").toLowerCase() : null; }
function showResult(selector, state, title, detail) {
  const box = $(selector); box.className = `result ${state}`; box.replaceChildren();
  const heading = document.createElement("h3"); const paragraph = document.createElement("p");
  heading.textContent = title; paragraph.textContent = detail; box.append(heading, paragraph);
}
function renderUrlScan(result) {
  const details = result.evidence.length ? result.evidence.map((item) => `${item.source}: ${item.detail}`).join(" ") : "No known malicious signals were found for this URL.";
  showResult("#scanResult", result.verdict, `${result.verdict.toUpperCase()} · ${result.risk_score}/100`, details);
}
async function sha1Hex(value) { const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(value)); return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase(); }
function setBusy(button, busy, label) { if (!button.dataset.label) button.dataset.label = button.textContent; button.disabled = busy; button.textContent = busy ? label : button.dataset.label; }

async function updateBlockedList() {
  const { blockedSites = [] } = await storageGet(["blockedSites"]); const list = $("#blockedList"); list.replaceChildren();
  if (!blockedSites.length) { const empty = document.createElement("li"); empty.className = "empty"; empty.textContent = "No blocked sites"; list.append(empty); }
  blockedSites.forEach((site) => { const item = document.createElement("li"); const label = document.createElement("span"); const remove = document.createElement("button"); label.textContent = site; remove.textContent = "Remove"; remove.className = "remove-site"; remove.addEventListener("click", async () => { await storageSet({ blockedSites: blockedSites.filter((value) => value !== site) }); updateBlockedList(); }); item.append(label, remove); list.append(item); });
}
async function addBlockedSite(value) { const hostname = hostnameFrom(value); if (!hostname) return alert("Enter a valid website or HTTP(S) URL."); const { blockedSites = [] } = await storageGet(["blockedSites"]); if (!blockedSites.includes(hostname)) blockedSites.push(hostname); await storageSet({ blockedSites }); await updateBlockedList(); }

document.addEventListener("DOMContentLoaded", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); currentTabUrl = tab && validWebUrl(tab.url) ? tab.url : "";
  $("#currentUrl").textContent = currentTabUrl || "This browser page cannot be scanned."; $("#urlInput").value = currentTabUrl;
  const saved = await storageGet(["apiUrl", "reportName", "reportEmail", "automaticScanning", "passwordDetection"]);
  $("#apiUrl").value = saved.apiUrl || DEFAULT_API; $("#reportName").value = saved.reportName || ""; $("#reportEmail").value = saved.reportEmail || "";
  $("#automaticScanning").checked = saved.automaticScanning !== false; $("#passwordDetection").checked = saved.passwordDetection !== false; await updateBlockedList();
  try { await apiRequest("/health"); $("#apiState").classList.add("online"); } catch (_) { $("#apiState").classList.add("offline"); }

  document.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => { item.classList.remove("active"); item.setAttribute("aria-selected", "false"); });
    document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.remove("active")); button.classList.add("active"); button.setAttribute("aria-selected", "true"); $(`#${button.dataset.tab}`).classList.add("active");
  }));

  $("#scanUrl").addEventListener("click", async (event) => {
    const parsed = validWebUrl($("#urlInput").value.trim()); if (!parsed) return showResult("#scanResult", "error", "Invalid URL", "Enter a valid website address.");
    setBusy(event.currentTarget, true, "Scanning…"); try { renderUrlScan(await apiRequest("/api/scan", { method: "POST", body: JSON.stringify({ url: parsed.href }) })); } catch (error) { showResult("#scanResult", "error", "Scan failed", error.message); } finally { setBusy(event.currentTarget, false); }
  });
  $("#scanIp").addEventListener("click", async (event) => {
    const ip = $("#ipInput").value.trim(); setBusy(event.currentTarget, true, "Checking…");
    try { const result = await apiRequest(`/api/ip/${encodeURIComponent(ip)}`); const location = [result.owner, result.network, result.country].filter(Boolean).join(" · "); showResult("#ipResult", result.verdict, `${result.verdict.toUpperCase()} · ${result.risk_score}/100`, `VirusTotal: ${result.malicious_detections} malicious and ${result.suspicious_detections} suspicious detections.${location ? ` ${location}` : ""}`); } catch (error) { showResult("#ipResult", "error", "IP check failed", error.message); } finally { setBusy(event.currentTarget, false); }
  });
  $("#checkPassword").addEventListener("click", async (event) => {
    let password = $("#passwordInput").value; if (!password) return showResult("#passwordResult", "error", "Password required", "Enter a password to check."); setBusy(event.currentTarget, true, "Checking…");
    try { const hash = await sha1Hex(password); password = ""; $("#passwordInput").value = ""; const result = await apiRequest(`/api/password/range/${hash.slice(0, 5)}`); const count = Number(result.matches[hash.slice(5)] || 0); showResult("#passwordResult", count ? "malicious" : "unknown", count ? "Breached password" : "No breach found", count ? `This password appears ${count.toLocaleString()} times in breach data. Do not use it.` : "This password was not found in HIBP. Use a unique password and enable multi-factor authentication."); } catch (error) { showResult("#passwordResult", "error", "Password check failed", error.message); } finally { password = ""; setBusy(event.currentTarget, false); }
  });
  $("#checkEmail").addEventListener("click", async (event) => {
    const email = $("#emailInput").value.trim(); if (!email) return showResult("#emailResult", "error", "Email required", "Enter an email address."); setBusy(event.currentTarget, true, "Checking…");
    try { const result = await apiRequest(`/api/breaches/${encodeURIComponent(email)}`); const names = result.breaches.map((item) => item.title).join(", "); showResult("#emailResult", result.breached ? "malicious" : "unknown", result.breached ? "Breaches found" : "No breach found", result.breached ? `Found in ${result.breaches.length} known breach${result.breaches.length === 1 ? "" : "es"}: ${names}` : "No known breach was returned for this email address."); } catch (error) { showResult("#emailResult", "error", "Email check failed", error.message); } finally { setBusy(event.currentTarget, false); }
  });
  $("#reportUrl").addEventListener("click", async (event) => {
    const name = $("#reportName").value.trim(); const email = $("#reportEmail").value.trim(); const url = $("#urlInput").value.trim(); const reason = $("#reportReason").value.trim();
    if (!name || !email || !validWebUrl(url)) { $("#reportState").textContent = "Name, email, and a valid URL are required."; return; }
    setBusy(event.currentTarget, true, "Submitting…"); try { await apiRequest("/api/report", { method: "POST", body: JSON.stringify({ name, email, malicious_url: url, reason: reason || null }) }); await storageSet({ reportName: name, reportEmail: email }); $("#reportState").textContent = "Report saved and added to Piranha community intelligence."; $("#reportReason").value = ""; } catch (error) { $("#reportState").textContent = `Report failed: ${error.message}`; } finally { setBusy(event.currentTarget, false); }
  });
  $("#addSite").addEventListener("click", async () => { await addBlockedSite($("#siteInput").value); $("#siteInput").value = ""; }); $("#blockCurrentSite").addEventListener("click", () => addBlockedSite(currentTabUrl));
  $("#saveSettings").addEventListener("click", async () => { const parsed = validWebUrl($("#apiUrl").value.trim()); if (!parsed) return alert("Enter a valid backend URL."); await storageSet({ apiUrl: parsed.href.replace(/\/$/, ""), automaticScanning: $("#automaticScanning").checked, passwordDetection: $("#passwordDetection").checked }); alert("Settings saved."); });
});
