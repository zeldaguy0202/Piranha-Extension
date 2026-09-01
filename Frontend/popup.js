document.addEventListener("DOMContentLoaded", function () {

  // --- Block Current Site ---
  document.getElementById("blockCurrentSite").addEventListener("click", function () {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs.length === 0) return;
      var url = new URL(tabs[0].url);
      var hostname = url.hostname.replace(/^www\./, ""); // strip www. prefix

      chrome.storage.sync.get("blockedSites", function (data) {
        var blockedSites = data.blockedSites || [];
        if (blockedSites.includes(hostname)) {
          alert(hostname + " is already blocked.");
          return;
        }
        blockedSites.push(hostname);
        chrome.storage.sync.set({ blockedSites: blockedSites }, function () {
          updateBlockedList();
        });
      });
    });
  });

  //-- Add Site Manually ---
  var addSiteButton = document.getElementById("addSite");
  addSiteButton.addEventListener("click", function () {
    var siteInput = document.getElementById("siteInput").value;
    if (siteInput) {
      chrome.storage.sync.get("blockedSites", function (data) {
        var blockedSites = data.blockedSites || [];
        blockedSites.push(siteInput);
        chrome.storage.sync.set({ blockedSites: blockedSites });
        updateBlockedList();
      });
      document.getElementById("siteInput").value = "";
    }
  });


  //--- Render Blocked List ---
  function updateBlockedList() {
    chrome.storage.sync.get("blockedSites", function (data) {
      var blockedSites = data.blockedSites;
      if (!blockedSites) {
        blockedSites = [];
      }
      var blockedList = document.getElementById("blockedList");
      blockedList.innerHTML = "";
      blockedSites.forEach(function (site) {
        var li = document.createElement("li");
        li.textContent = site;

        // add a remove button

        var removeButton = document.createElement("button");
        removeButton.textContent = "Remove";
        removeButton.id = "removeSite";
        removeButton.addEventListener("click", function () {
          chrome.storage.sync.get("blockedSites", function (data) {
            var blockedSites = data.blockedSites;
            var index = blockedSites.indexOf(site);
            if (index !== -1) {
              blockedSites.splice(index, 1);
              chrome.storage.sync.set({ blockedSites: blockedSites });
              updateBlockedList();
            }
          });
        });

        li.appendChild(removeButton);

        blockedList.appendChild(li);
      });
    });
  }

  updateBlockedList();
});
