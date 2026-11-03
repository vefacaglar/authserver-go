import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The SPA is served on the same origin as the Go API in production
// (Caddy routes /api, /admin/api, /connect and /.well-known to Go and
// everything else to this build). In development the proxy below
// recreates that split against a locally running authserver.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:5175",
      "/admin/api": "http://localhost:5175",
      "/connect": "http://localhost:5175",
      "/.well-known": "http://localhost:5175",
    },
  },
});
