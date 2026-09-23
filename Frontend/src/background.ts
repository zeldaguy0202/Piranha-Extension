import { normalizeHost } from "./lib/normalizeHost";

const BLOCKED_SITES_API_URL = "http://127.0.0.1:8000/api/blocked-sites";
const SYNC_ALARM_NAME = "piranha-community-sync";
const SYNC_INTERVAL_MINUTES = 5;

async function syncCommunityBlockedSites() {
  try {
    const response = await fetch(BLOCKED_SITES_API_URL);
    if (!response.ok) return;

    const data: { sites?: string[] } = await response.json();
    const hostnames = Array.from(
      new Set((data.sites || []).map(normalizeHost).filter(Boolean))
    );

    await chrome.storage.sync.set({ communityBlockedSites: hostnames });
  } catch {
    // Keep the previously cached list if the backend is unreachable.
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(SYNC_ALARM_NAME, { periodInMinutes: SYNC_INTERVAL_MINUTES });
  syncCommunityBlockedSites();
});

chrome.runtime.onStartup.addListener(() => {
  syncCommunityBlockedSites();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SYNC_ALARM_NAME) {
    syncCommunityBlockedSites();
  }
});
