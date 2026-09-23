import React, { useEffect, useState } from "react";
import { Send, CheckCircle2 } from "lucide-react";
import logo from "../ChatGPT Image Sep 2, 2026 at 07_04_27 PM.png";
import { normalizeHost } from "./lib/normalizeHost";

const REPORT_API_URL = "http://127.0.0.1:8000/api/report";

export default function PiranhaPopup() {
  const [blockedSites, setBlockedSites] = useState<string[]>([]);
  const [communityBlockedSites, setCommunityBlockedSites] = useState<string[]>([]);
  const [siteInput, setSiteInput] = useState("");
  const [blockError, setBlockError] = useState("");

  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [reason, setReason] = useState("");
  const [details, setDetails] = useState("");
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState("");

  useEffect(() => {
    chrome.storage.sync.get(["blockedSites", "communityBlockedSites"], (data) => {
      setBlockedSites(data.blockedSites || []);
      setCommunityBlockedSites(data.communityBlockedSites || []);
    });

    const onChanged = (
      changes: { [key: string]: chrome.storage.StorageChange },
      areaName: string
    ) => {
      if (areaName !== "sync") return;
      if (changes.blockedSites) {
        setBlockedSites((changes.blockedSites.newValue as string[]) || []);
      }
      if (changes.communityBlockedSites) {
        setCommunityBlockedSites((changes.communityBlockedSites.newValue as string[]) || []);
      }
    };
    chrome.storage.onChanged.addListener(onChanged);
    return () => chrome.storage.onChanged.removeListener(onChanged);
  }, []);

  const addSite = (rawHost: string) => {
    const host = normalizeHost(rawHost);
    if (!host) {
      setBlockError("Enter a valid site to block.");
      return;
    }
    chrome.storage.sync.get("blockedSites", (data) => {
      const sites: string[] = data.blockedSites || [];
      if (sites.includes(host)) {
        setBlockError(`${host} is already blocked.`);
        return;
      }
      const updated = [...sites, host];
      chrome.storage.sync.set({ blockedSites: updated }, () => {
        setBlockedSites(updated);
        setBlockError("");
      });
    });
  };

  const handleAddSite = () => {
    addSite(siteInput);
    setSiteInput("");
  };

  const handleBlockCurrentSite = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeUrl = tabs[0]?.url;
      if (!activeUrl || !activeUrl.startsWith("http")) {
        setBlockError("This page can't be blocked.");
        return;
      }
      addSite(activeUrl);
    });
  };

  const removeSite = (site: string) => {
    const updated = blockedSites.filter((s) => s !== site);
    chrome.storage.sync.set({ blockedSites: updated }, () => {
      setBlockedSites(updated);
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError("");

    if (!name || !url || !reason || !details || !email) {
      setSubmitError("Please fill out all fields.");
      return;
    }

    setSubmitting(true);
    try {
      const response = await fetch(REPORT_API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          email,
          malicious_url: url,
          reason: `${reason}: ${details}`,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => null);
        throw new Error(errorBody?.detail || "Report submission failed.");
      }

      setSubmitted(true);
    } catch (error) {
      setSubmitError(
        error instanceof Error ? error.message : "Report submission failed."
      );
    } finally {
      setSubmitting(false);
    }
  };

  const resetForm = () => {
    setSubmitted(false);
    setName("");
    setUrl("");
    setReason("");
    setDetails("");
    setEmail("");
    setSubmitError("");
  };

  return (
    <div className="popup">
      <img src={logo} className="logo" alt="Piranha logo" />

      <section className="card">
        <h3 className="section-title">Blocked Websites</h3>

        <ul className="blocked-list">
          {blockedSites.length === 0 && (
            <li className="blocked-empty">No sites blocked yet.</li>
          )}
          {blockedSites.map((site) => (
            <li key={site} className="blocked-item">
              <span>{site}</span>
              <button
                type="button"
                className="remove-button"
                onClick={() => removeSite(site)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>

        <div className="add-site-form">
          <input
            type="text"
            value={siteInput}
            onChange={(e) => setSiteInput(e.target.value)}
            placeholder="e.g. example.com"
          />
          <button type="button" onClick={handleAddSite}>
            Add Site
          </button>
          <button type="button" onClick={handleBlockCurrentSite}>
            Block Current Site
          </button>
          {blockError && <p className="error-text">{blockError}</p>}
        </div>
      </section>

      <section className="card">
        <h3 className="section-title">Community Reported Sites</h3>
        <p className="section-subtitle">
          Synced automatically from approved community reports.
        </p>

        <ul className="blocked-list">
          {communityBlockedSites.length === 0 && (
            <li className="blocked-empty">No community sites synced yet.</li>
          )}
          {communityBlockedSites.map((site) => (
            <li key={site} className="blocked-item">
              <span>{site}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        {!submitted ? (
          <>
            <h3 className="section-title">Report a Website</h3>
            <p className="section-subtitle">
              Tell the Piranha community what you found.
            </p>

            <form onSubmit={handleSubmit} className="report-form">
              <label>
                Your name
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Jane Doe"
                />
              </label>

              <label>
                Website URL
                <input
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                />
              </label>

              <label>
                Why should this website be blocked?
                <select value={reason} onChange={(e) => setReason(e.target.value)}>
                  <option value="">Select a reason</option>
                  <option value="Phishing">Phishing</option>
                  <option value="Malware">Malware</option>
                  <option value="Scam">Scam or Fraud</option>
                  <option value="Suspicious">Suspicious Website</option>
                  <option value="Fake Website">Fake Website</option>
                  <option value="Other">Other</option>
                </select>
              </label>

              <label>
                Details
                <textarea
                  value={details}
                  onChange={(e) => setDetails(e.target.value)}
                  placeholder="Describe what made this website suspicious..."
                  rows={3}
                />
              </label>

              <label>
                Email address
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                />
              </label>

              {submitError && <p className="error-text">{submitError}</p>}

              <button type="submit" className="primary-button" disabled={submitting}>
                <Send size={16} />
                {submitting ? "Submitting..." : "Submit Report"}
              </button>
            </form>
          </>
        ) : (
          <div className="success">
            <CheckCircle2 className="success-icon" size={40} />
            <h3 className="section-title">Thank you for your report!</h3>
            <p className="section-subtitle">
              Your report has been submitted to the Piranha community.
            </p>
            <button type="button" onClick={resetForm}>
              Submit Another Report
            </button>
          </div>
        )}
      </section>

      <p className="privacy-note">
        🔒 Your information is handled securely and used only to improve
        community protection.
      </p>
    </div>
  );
}
