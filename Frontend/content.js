chrome.storage.sync.get(["blockedSites", "communityBlockedSites"], function(data) {
  var blockedSites = (data.blockedSites || []).concat(data.communityBlockedSites || []);

  for (var i = 0; i < blockedSites.length; i++) {
    if (window.location.href.includes(blockedSites[i])) {
      
      // empty the content of the page
      document.documentElement.innerHTML = "";
    }
  }
});
