import { defineManifest } from "@crxjs/vite-plugin";
import { API_BASE_URL } from "./config";

export default defineManifest({
  manifest_version: 3,
  name: "Piranha",
  description: "Blocks and reports unsafe websites.",
  version: "1.0.0",
  key: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAymN1Fo/CMY1aGJefzlzwB3sAKesSzEPqN2Ii50iGafF9KH6dpfj7iTTKbzmGDY7HC+zBknZhu/TsdX8nPXoeG7KdeLiYkKspHDNpPE8HUjIwSzS7wVOGzPRfZzgqRyc+Q3p55s/mvBlI/n2RTFR3L2yVVa9YsyPu3EvwhRNokT0+6oxjQj1OA5xSv5gDKwLsr1PBIUYiwUpKCgkkmAEC6iqHL7hbfB1Xskp9OOyLOf6+cC8/Zj2WmL8E/p0VkJAQWHUdhDw4Z4vBW4PjkRpgI89CfiNiOF75pEt3q82dMiB4lnVXpdRQdIig5k+GH6puhCMaE2A/15jcJZjc+fsVsQIDAQAB",
  permissions: ["storage", "tabs", "alarms"],
  host_permissions: ["*://*/*", `${API_BASE_URL}/*`],
  background: {
    service_worker: "src/background.ts",
    type: "module",
  },
  action: {
    default_popup: "index.html",
    default_icon: "Piranha_Extension_Logo.png",
  },
  content_scripts: [
    {
      matches: ["<all_urls>"],
      js: ["content.js"],
    },
  ],
});

