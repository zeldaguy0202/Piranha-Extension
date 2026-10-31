chrome.storage.sync.get(
  ["blockedSites", "communityBlockedSites", "ignoredCommunitySites"],
  function(data) {
    var ignoredSites = data.ignoredCommunitySites || [];
    var blockedSites = (data.blockedSites || []).concat(
      (data.communityBlockedSites || []).filter(function(site) {
        return !ignoredSites.includes(site);
      })
    );
    var hostname = window.location.hostname.replace(/^www\./, "");

    for (var i = 0; i < blockedSites.length; i++) {
      var blockedHost = blockedSites[i].toLowerCase().replace(/^www\./, "");
      if (hostname === blockedHost || hostname.endsWith("." + blockedHost)) {
        document.documentElement.innerHTML = "";
        return;
      }
    }
  }
);
