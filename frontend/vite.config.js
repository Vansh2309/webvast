import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The backend runs on :8000. Proxy /api so the frontend can use same-origin fetches.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
    },
  },
});
