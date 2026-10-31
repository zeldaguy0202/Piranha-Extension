const $ = (selector) => document.querySelector(selector);

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

async function loadDashboard() {
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
    $("#statThreats").textContent = stats.confirmed_provider_matches.toLocaleString();
    $("#statIndicators").textContent = stats.trusted_indicators.toLocaleString();
    $("#statReports").textContent = stats.reports.toLocaleString();
    $("#statReporters").textContent = stats.reporters.toLocaleString();

    const rows = $("#threatRows");
    rows.replaceChildren();
    if (!stats.recent_threats.length) {
      const row = document.createElement("tr");
      const cell = text("td", "No confirmed provider matches have been cached yet.", "empty");
      cell.colSpan = 3;
      row.append(cell);
      rows.append(row);
    } else {
      stats.recent_threats.forEach((item) => {
        const row = document.createElement("tr");
        const url = text("td", item.url, "url-cell");
        url.title = item.url;
        row.append(url, text("td", item.sources.join(", ")), text("td", new Date(item.checked_at).toLocaleString()));
        rows.append(row);
      });
    }

  } catch (_) {
    $("#threatRows").innerHTML = '<tr><td colspan="3" class="empty">Dashboard data is unavailable.</td></tr>';
  }
}

$("#scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(event.currentTarget, true, "Scanning…");
  try {
    renderScan(await request("/api/scan", { method: "POST", body: JSON.stringify({ url: $("#urlInput").value.trim() }) }));
    loadDashboard();
  } catch (error) {
    const panel = $("#scanResult");
    panel.className = "result-panel malicious";
    panel.replaceChildren(text("strong", "Scan unavailable"), text("p", error.message));
  } finally {
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
    event.currentTarget.reset();
    loadDashboard();
  } catch (error) {
    output.className = "tool-result bad";
    output.textContent = error.message;
  } finally {
    setBusy(event.currentTarget, false);
  }
});

loadDashboard();
