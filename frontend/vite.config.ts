import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In development the FastAPI backend runs on :8080 (override with NV_API_URL).
const api = process.env.NV_API_URL ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api/ws": { target: api.replace(/^http/, "ws"), ws: true, changeOrigin: false },
      "/api": { target: api, changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
});
