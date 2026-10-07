import React, { useEffect, useState } from "react";
import { Send, CheckCircle2 } from "lucide-react";
import logo from "../ChatGPT Image Sep 2, 2026 at 07_04_27 PM.png";
import { normalizeHost } from "./lib/normalizeHost";
import { API_BASE_URL } from "./config";

const REPORT_API_URL = `${API_BASE_URL}/api/report`;
const BLOCKED_SITES_API_URL = `${API_BASE_URL}/api/blocked-sites`;

type TabKey = "blocklist" | "report";

const TABS: { key: TabKey; label: string }[] = [
  { key: "blocklist", label: "Blocked Sites" },
  { key: "report", label: "Report" },
];

export default function PiranhaPopup() {
  const [activeTab, setActiveTab] = useState<TabKey>("blocklist");
  const [blockedSites, setBlockedSites] = useState<string[]>([]);
  const [communityBlockedSites, setCommunityBlockedSites] = useState<string[]>([]);
  const [ignoredCommunitySites, setIgnoredCommunitySites] = useState<string[]>([]);
  const [siteInput, setSiteInput] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [blockError, setBlockError] = useState("");

  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [reason, setReason] = useState("");
  const [details, setDetails] = useState("");
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState("");

  const effectiveBlockedSites = Array.from(
    new Set([
      ...blockedSites,
      ...communityBlockedSites.filter((site) => !ignoredCommunitySites.includes(site)),
    ])
  );
  const filteredBlockedSites = effectiveBlockedSites.filter((site) =>
    site.toLowerCase().includes(searchQuery.trim().toLowerCase())
  );

  useEffect(() => {
    chrome.storage.sync.get(
      ["blockedSites", "communityBlockedSites", "ignoredCommunitySites"],
      (data) => {
      setBlockedSites(data.blockedSites || []);
      setCommunityBlockedSites(data.communityBlockedSites || []);
      setIgnoredCommunitySites(data.ignoredCommunitySites || []);
      }
    );

    fetch(BLOCKED_SITES_API_URL)
      .then((response) => (response.ok ? response.json() : null))
      .then((data: { sites?: string[] } | null) => {
        if (!data) return;
        const hostnames = Array.from(
          new Set((data.sites || []).map(normalizeHost).filter(Boolean))
        );
        chrome.storage.sync.set({ communityBlockedSites: hostnames });
      })
      .catch(() => undefined);

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
      if (changes.ignoredCommunitySites) {
        setIgnoredCommunitySites((changes.ignoredCommunitySites.newValue as string[]) || []);
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
    chrome.storage.sync.get(
      ["blockedSites", "communityBlockedSites", "ignoredCommunitySites"],
      (data) => {
      const sites: string[] = data.blockedSites || [];
      const communitySites: string[] = data.communityBlockedSites || [];
      const ignoredSites: string[] = data.ignoredCommunitySites || [];
      const alreadyBlocked =
        (sites.includes(host) || communitySites.includes(host)) &&
        !ignoredSites.includes(host);
      if (alreadyBlocked) {
        setBlockError(`${host} is already blocked.`);
        return;
      }
      const updatedSites = sites.includes(host) ? sites : [...sites, host];
      const updatedIgnoredSites = ignoredSites.filter((site) => site !== host);
      chrome.storage.sync.set(
        { blockedSites: updatedSites, ignoredCommunitySites: updatedIgnoredSites },
        () => {
        setBlockedSites(updatedSites);
        setIgnoredCommunitySites(updatedIgnoredSites);
        setBlockError("");
        }
      );
      }
    );
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
    const updatedSites = blockedSites.filter((entry) => entry !== site);
    const updatedIgnoredSites = communityBlockedSites.includes(site)
      ? Array.from(new Set([...ignoredCommunitySites, site]))
      : ignoredCommunitySites;
    chrome.storage.sync.set(
      { blockedSites: updatedSites, ignoredCommunitySites: updatedIgnoredSites },
      () => {
        setBlockedSites(updatedSites);
        setIgnoredCommunitySites(updatedIgnoredSites);
      }
    );
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

      <div className="tab-bar" role="group" aria-label="Popup sections">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            className="tab-button"
            aria-pressed={activeTab === tab.key}
            data-active={activeTab === tab.key}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "blocklist" && (
      <section className="card">
        <h3 className="section-title">Blocked Websites</h3>

        <input
          type="search"
          className="blocklist-search"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search blocked sites"
          aria-label="Search blocked sites"
        />

        <ul className="blocked-list">
          {effectiveBlockedSites.length === 0 && (
            <li className="blocked-empty">No sites blocked yet.</li>
          )}
          {effectiveBlockedSites.length > 0 && filteredBlockedSites.length === 0 && (
            <li className="blocked-empty">No matching sites found.</li>
          )}
          {filteredBlockedSites.map((site) => (
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
      )}

      {activeTab === "report" && (
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
              We will notify you at a later date if the site is approved for
              our list.
            </p>
            <button type="button" onClick={resetForm}>
              Submit Another Report
            </button>
          </div>
        )}
      </section>
      )}

      <p className="privacy-note">
        🔒 Your information is handled securely and used only to improve
        community protection.
      </p>
    </div>
  );
}
