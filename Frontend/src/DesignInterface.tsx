import React, { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, ShieldCheck } from "lucide-react";
import logo from "../ChatGPT Image Sep 2, 2026 at 07_04_27 PM.png";
import { normalizeHost } from "./lib/normalizeHost";
import { API_BASE_URL } from "./config";

type TabKey = "url" | "password";
type ResultState = { tone: "good" | "warn" | "bad"; title: string; detail: string } | null;

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body as T;
}

async function sha1Hex(value: string) {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function Result({ value }: { value: ResultState }) {
  if (!value) return null;
  const Icon = value.tone === "good" ? CheckCircle2 : AlertTriangle;
  return <div className={`result ${value.tone}`}><Icon size={18} /><div><strong>{value.title}</strong><p>{value.detail}</p></div></div>;
}

export default function PiranhaPopup() {
  const [tab, setTab] = useState<TabKey>("url");
  const [online, setOnline] = useState<boolean | null>(null);
  const [currentUrl, setCurrentUrl] = useState("");
  const [url, setUrl] = useState("");
  const [urlResult, setUrlResult] = useState<ResultState>(null);
  const [ip, setIp] = useState("");
  const [ipResult, setIpResult] = useState<ResultState>(null);
  const [busy, setBusy] = useState("");
  const [blockedSites, setBlockedSites] = useState<string[]>([]);
  const [communitySites, setCommunitySites] = useState<string[]>([]);
  const [ignoredSites, setIgnoredSites] = useState<string[]>([]);
  const [siteInput, setSiteInput] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [reason, setReason] = useState("");
  const [reportResult, setReportResult] = useState<ResultState>(null);
  const [password, setPassword] = useState("");
  const [passwordResult, setPasswordResult] = useState<ResultState>(null);
  const [breachEmail, setBreachEmail] = useState("");
  const [emailResult, setEmailResult] = useState<ResultState>(null);

  const effectiveBlocked = useMemo(() => Array.from(new Set([
    ...blockedSites,
    ...communitySites.filter((site) => !ignoredSites.includes(site)),
  ])).sort(), [blockedSites, communitySites, ignoredSites]);

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, ([active]) => {
      const activeUrl = active?.url?.startsWith("http") ? active.url : "";
      setCurrentUrl(activeUrl); setUrl(activeUrl);
    });
    chrome.storage.sync.get(["blockedSites", "communityBlockedSites", "ignoredCommunitySites", "reportName", "reportEmail"], (data) => {
      setBlockedSites(data.blockedSites || []); setCommunitySites(data.communityBlockedSites || []);
      setIgnoredSites(data.ignoredCommunitySites || []); setName(data.reportName || ""); setEmail(data.reportEmail || "");
    });
    api<{ status: string }>("/health").then(() => setOnline(true)).catch(() => setOnline(false));
    api<{ sites: string[] }>("/api/blocked-sites").then((data) => {
      const sites = Array.from(new Set(data.sites.map(normalizeHost).filter(Boolean)));
      setCommunitySites(sites); chrome.storage.sync.set({ communityBlockedSites: sites });
    }).catch(() => undefined);
  }, []);

  const saveLists = (local: string[], ignored: string[]) => {
    setBlockedSites(local); setIgnoredSites(ignored);
    chrome.storage.sync.set({ blockedSites: local, ignoredCommunitySites: ignored });
  };

  const addBlocked = (raw: string) => {
    const host = normalizeHost(raw);
    if (!host) return;
    saveLists(Array.from(new Set([...blockedSites, host])), ignoredSites.filter((item) => item !== host));
    setSiteInput("");
  };

  const removeBlocked = (host: string) => {
    saveLists(blockedSites.filter((item) => item !== host), communitySites.includes(host) ? Array.from(new Set([...ignoredSites, host])) : ignoredSites);
  };

  const scanUrl = async () => {
    if (!url.trim()) return;
    setBusy("url"); setUrlResult(null);
    try {
      const result = await api<any>("/api/scan", { method: "POST", body: JSON.stringify({ url: url.trim() }) });
      const evidence = result.evidence?.length ? result.evidence.map((item: any) => `${item.source}: ${item.detail}`).join(" ") : "No known malicious signals were found.";
      setUrlResult({ tone: result.verdict === "malicious" ? "bad" : result.verdict === "suspicious" ? "warn" : "good", title: `${result.verdict.toUpperCase()} · ${result.risk_score}/100`, detail: evidence });
    } catch (error) { setUrlResult({ tone: "bad", title: "Scan failed", detail: (error as Error).message }); }
    finally { setBusy(""); }
  };

  const scanIp = async () => {
    setBusy("ip"); setIpResult(null);
    try {
      const result = await api<any>(`/api/ip/${encodeURIComponent(ip.trim())}`);
      setIpResult({ tone: result.verdict === "malicious" ? "bad" : result.verdict === "suspicious" ? "warn" : "good", title: `${result.verdict.toUpperCase()} · ${result.risk_score}/100`, detail: `VirusTotal found ${result.malicious_detections} malicious and ${result.suspicious_detections} suspicious detections.` });
    } catch (error) { setIpResult({ tone: "bad", title: "IP check failed", detail: (error as Error).message }); }
    finally { setBusy(""); }
  };

  const reportUrl = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy("report"); setReportResult(null);
    try {
      await api("/api/report", { method: "POST", body: JSON.stringify({ name, email, malicious_url: url, reason: reason || null }) });
      chrome.storage.sync.set({ reportName: name, reportEmail: email });
      setReportResult({ tone: "good", title: "Report saved", detail: "Your report is now part of Piranha community intelligence." }); setReason("");
    } catch (error) { setReportResult({ tone: "bad", title: "Report failed", detail: (error as Error).message }); }
    finally { setBusy(""); }
  };

  const checkPassword = async () => {
    if (!password) return; setBusy("password"); setPasswordResult(null);
    try {
      const hash = await sha1Hex(password); setPassword("");
      const result = await api<any>(`/api/password/range/${hash.slice(0, 5)}`);
      const count = Number(result.matches[hash.slice(5)] || 0);
      setPasswordResult({ tone: count ? "bad" : "good", title: count ? "Breached password" : "No breach found", detail: count ? `Found ${count.toLocaleString()} times in HIBP. Do not use this password.` : "Not found in HIBP. Still use a unique password and MFA." });
    } catch (error) { setPasswordResult({ tone: "bad", title: "Password check failed", detail: (error as Error).message }); }
    finally { setBusy(""); }
  };

  const checkEmail = async () => {
    setBusy("email"); setEmailResult(null);
    try {
      const result = await api<any>(`/api/breaches/${encodeURIComponent(breachEmail.trim())}`);
      setEmailResult({ tone: result.breached ? "bad" : "good", title: result.breached ? "Breaches found" : "No breach found", detail: result.breached ? result.breaches.map((item: any) => item.title).join(", ") : "No breach was returned for this test address." });
    } catch (error) { setEmailResult({ tone: "bad", title: "Email check failed", detail: (error as Error).message }); }
    finally { setBusy(""); }
  };

  return <div className="popup">
    <header><img src={logo} className="logo" alt="Piranha logo" /><div><h1>Piranha</h1><p>Proactive browser protection</p></div><span className={`health ${online ? "online" : online === false ? "offline" : ""}`} title="Backend status" /></header>
    <nav className="tab-bar" aria-label="Security tools">
      <button className={tab === "url" ? "active" : ""} onClick={() => setTab("url")}>URL Check</button>
      <button className={tab === "password" ? "active" : ""} onClick={() => setTab("password")}>Password Check</button>
    </nav>

    {tab === "url" && <div className="panel-stack">
      <section className="card"><h2><ShieldCheck size={18} /> Check a URL</h2><p className="muted ellipsis">{currentUrl || "Enter a website address"}</p><input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" /><button onClick={scanUrl} disabled={busy === "url"}>{busy === "url" ? "Scanning…" : "Scan URL"}</button><Result value={urlResult} /></section>
      <section className="card compact"><h2>VirusTotal IP reputation</h2><div className="row"><input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="8.8.8.8" /><button onClick={scanIp} disabled={busy === "ip"}>Check</button></div><Result value={ipResult} /></section>
      <details className="card"><summary>Personal & community blocklist ({effectiveBlocked.length})</summary><ul className="blocked-list">{effectiveBlocked.map((site) => <li key={site}><span>{site}</span><button onClick={() => removeBlocked(site)}>Remove</button></li>)}</ul><div className="row"><input value={siteInput} onChange={(e) => setSiteInput(e.target.value)} placeholder="example.com" /><button onClick={() => addBlocked(siteInput)}>Add</button></div><button className="secondary" onClick={() => addBlocked(currentUrl)}>Block current site</button></details>
      <details className="card"><summary>Report this URL</summary><form onSubmit={reportUrl} className="form-stack"><input value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name" required /><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Your email" required /><textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why is this URL suspicious?" /><button disabled={busy === "report"}>{busy === "report" ? "Submitting…" : "Submit report"}</button></form><Result value={reportResult} /></details>
    </div>}

    {tab === "password" && <div className="panel-stack">
      <section className="card"><h2>Password breach check</h2><p className="muted">Your password never leaves Chrome. Only five SHA-1 hash characters are sent using HIBP k-anonymity.</p><input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter a password" /><button onClick={checkPassword} disabled={busy === "password"}>{busy === "password" ? "Checking…" : "Check password"}</button><Result value={passwordResult} /></section>
      <section className="card"><h2>Email breach demo</h2><p className="muted">Uses HIBP's official integration-test service.</p><input type="email" value={breachEmail} onChange={(e) => setBreachEmail(e.target.value)} placeholder="account-exists@hibp-integration-tests.com" /><button onClick={checkEmail} disabled={busy === "email"}>{busy === "email" ? "Checking…" : "Check test email"}</button><Result value={emailResult} /></section>
    </div>}
    <footer>Results are security signals, not guarantees.</footer>
  </div>;
}
