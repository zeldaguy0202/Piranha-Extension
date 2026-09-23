import { defineManifest } from "@crxjs/vite-plugin";

export default defineManifest({
  manifest_version: 3,
  name: "Piranha",
  description: "Blocks and reports unsafe websites.",
  version: "1.0.0",
  permissions: ["storage", "tabs", "alarms"],
  host_permissions: ["*://*/*", "http://127.0.0.1:8000/*"],
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