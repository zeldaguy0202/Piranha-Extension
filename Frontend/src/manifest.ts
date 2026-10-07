import { defineManifest } from "@crxjs/vite-plugin";
import { API_BASE_URL } from "./config";

export default defineManifest({
  manifest_version: 3,
  name: "Piranha",
  description: "Blocks and reports unsafe websites.",
  version: "1.0.0",
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