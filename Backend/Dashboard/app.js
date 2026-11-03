const $ = (selector) => document.querySelector(selector);
let recentThreats = [];
let refreshTimer;

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed with HTTP ${response.status}`);
  return data;
}

function setBusy(form, busy, label) {
  const button = form.querySelector('button[type="submit"]');
  if (!button.dataset.label) button.dataset.label = button.textContent;
  button.disabled = busy;
  button.textContent = busy ? label : button.dataset.label;
}

function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(toast.hideTimer);
  toast.hideTimer = window.setTimeout(() => toast.classList.remove("visible"), 2600);
}

function animateNumber(node, target) {
  const start = Number(node.textContent.replace(/,/g, "")) || 0;
  const started = performance.now();
  const duration = 500;
  function frame(now) {
    const progress = Math.min(1, (now - started) / duration);
    const eased = 1 - Math.pow(1 - progress, 3);
    node.textContent = Math.round(start + (target - start) * eased).toLocaleString();
    if (progress < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function renderThreatRows() {
  const rows = $("#threatRows");
  const query = $("#threatFilter").value.trim().toLowerCase();
  const filtered = recentThreats.filter((item) => `${item.url} ${item.sources.join(" ")}`.toLowerCase().includes(query));
  rows.replaceChildren();
  if (!filtered.length) {
    const row = document.createElement("tr");
    const message = recentThreats.length ? "No activity matches this filter." : "No confirmed provider matches have been cached yet.";
    const cell = text("td", message, "empty");
    cell.colSpan = 3;
    row.append(cell);
    rows.append(row);
    return;
  }
  filtered.forEach((item) => {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.title = "Click to copy this URL";
    row.addEventListener("click", async () => {
      await navigator.clipboard.writeText(item.url).catch(() => undefined);
      showToast("URL copied to clipboard");
    });
    const url = text("td", item.url, "url-cell");
    url.title = item.url;
    row.append(url, text("td", item.sources.join(", ")), text("td", new Date(item.checked_at).toLocaleString()));
    rows.append(row);
  });
}

function renderScan(result) {
  const panel = $("#scanResult");
  panel.replaceChildren();
  panel.className = `result-panel ${result.verdict}`;
  const header = document.createElement("div");
  header.className = "result-header";
  const heading = document.createElement("div");
  heading.append(text("div", result.verdict, "verdict"), text("div", result.normalized_url));
  header.append(heading, text("span", `${result.risk_score}/100`, "score"));
  panel.append(header);

  const list = document.createElement("ul");
  list.className = "evidence-list";
  if (result.evidence.length) {
    result.evidence.forEach((item) => list.append(text("li", `${item.source}: ${item.detail}`)));
  } else {
    list.append(text("li", "No strong warning evidence was found by the available sources. This does not prove the link is safe."));
  }
  panel.append(list);
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadDashboard(showFeedback = false) {
  const refresh = $("#refreshDashboard");
  refresh.classList.add("loading");
  try {
    await request("/health");
    $("#apiHealth").className = "health online";
    $("#apiHealth").lastChild.textContent = " API online";
  } catch (_) {
    $("#apiHealth").className = "health offline";
    $("#apiHealth").lastChild.textContent = " API offline";
  }

  try {
    const stats = await request("/api/dashboard/stats");
    animateNumber($("#statThreats"), stats.confirmed_provider_matches);
    animateNumber($("#statIndicators"), stats.trusted_indicators);
    animateNumber($("#statReports"), stats.reports);
    animateNumber($("#statReporters"), stats.reporters);
    recentThreats = stats.recent_threats;
    renderThreatRows();
    $("#lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}`;
    if (showFeedback) showToast("Dashboard data refreshed");

  } catch (_) {
    $("#threatRows").innerHTML = '<tr><td colspan="3" class="empty">Dashboard data is unavailable.</td></tr>';
  } finally {
    refresh.classList.remove("loading");
  }
}

$("#scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(event.currentTarget, true, "Scanning…");
  $("#scanProgress").classList.remove("hidden");
  $("#scanResult").classList.add("hidden");
  try {
    renderScan(await request("/api/scan", { method: "POST", body: JSON.stringify({ url: $("#urlInput").value.trim() }) }));
    loadDashboard();
  } catch (error) {
    const panel = $("#scanResult");
    panel.className = "result-panel malicious";
    panel.replaceChildren(text("strong", "Scan unavailable"), text("p", error.message));
  } finally {
    $("#scanProgress").classList.add("hidden");
    setBusy(event.currentTarget, false);
  }
});

async function sha1Hex(value) {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

$("#passwordForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const output = $("#passwordResult");
  setBusy(event.currentTarget, true, "Checking…");
  let password = $("#passwordInput").value;
  try {
    const hash = await sha1Hex(password);
    password = "";
    $("#passwordInput").value = "";
    const result = await request(`/api/password/range/${hash.slice(0, 5)}`);
    const count = Number(result.matches[hash.slice(5)] || 0);
    output.className = `tool-result ${count ? "bad" : "good"}`;
    output.textContent = count
      ? `Found ${count.toLocaleString()} times in known breach data. Choose a different password.`
      : "Not found in HIBP Pwned Passwords. This does not guarantee that the password is strong.";
  } catch (error) {
    output.className = "tool-result bad";
    output.textContent = error.message;
  } finally {
    password = "";
    setBusy(event.currentTarget, false);
  }
});

$("#emailForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const output = $("#emailResult");
  setBusy(event.currentTarget, true, "Checking…");
  try {
    const email = encodeURIComponent($("#emailInput").value.trim());
    const result = await request(`/api/breaches/${email}`);
    output.className = `tool-result ${result.breached ? "bad" : "good"}`;
    output.textContent = result.breached
      ? `Found in ${result.breaches.length} known breach${result.breaches.length === 1 ? "" : "es"}: ${result.breaches.map((item) => item.title).join(", ")}`
      : "No breach was returned for this address.";
  } catch (error) {
    output.className = "tool-result info";
    output.textContent = error.message;
  } finally {
    setBusy(event.currentTarget, false);
  }
});

$("#ipForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const output = $("#ipResult");
  setBusy(event.currentTarget, true, "Checking…");
  try {
    const result = await request(`/api/ip/${encodeURIComponent($("#ipInput").value.trim())}`);
    const details = [result.owner, result.network, result.country].filter(Boolean).join(" · ");
    output.className = `tool-result ${result.verdict === "unknown" ? "good" : "bad"}`;
    output.textContent = `${result.verdict.toUpperCase()}: ${result.malicious_detections} malicious and ${result.suspicious_detections} suspicious VirusTotal detections${details ? `. ${details}` : ""}.`;
  } catch (error) {
    output.className = "tool-result bad";
    output.textContent = error.message;
  } finally {
    setBusy(event.currentTarget, false);
  }
});

$("#reportForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const output = $("#reportResult");
  const form = new FormData(event.currentTarget);
  setBusy(event.currentTarget, true, "Submitting…");
  try {
    const payload = Object.fromEntries(form.entries());
    if (!payload.reason) payload.reason = null;
    await request("/api/report", { method: "POST", body: JSON.stringify(payload) });
    output.className = "tool-result good";
    output.textContent = "Report accepted. It will remain unverified until corroborated.";
    showToast("Community report saved");
    event.currentTarget.reset();
    loadDashboard();
  } catch (error) {
    output.className = "tool-result bad";
    output.textContent = error.message;
  } finally {
    setBusy(event.currentTarget, false);
  }
});

document.querySelectorAll("[data-url-example]").forEach((button) => {
  button.addEventListener("click", () => {
    $("#urlInput").value = button.dataset.urlExample;
    $("#urlInput").focus();
  });
});

$("#threatFilter").addEventListener("input", renderThreatRows);
$("#refreshDashboard").addEventListener("click", () => loadDashboard(true));

const sections = document.querySelectorAll("main section[id]");
const navLinks = document.querySelectorAll("nav a");
const observer = new IntersectionObserver((entries) => {
  const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
  if (!visible) return;
  navLinks.forEach((link) => link.classList.toggle("active", link.getAttribute("href") === `#${visible.target.id}`));
}, { rootMargin: "-25% 0px -60%", threshold: [0, .25, .5] });
sections.forEach((section) => observer.observe(section));

loadDashboard();
refreshTimer = window.setInterval(() => {
  if (!document.hidden) loadDashboard();
}, 30000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) loadDashboard();
});
