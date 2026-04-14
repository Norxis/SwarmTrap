import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/ui/",
  server: {
    proxy: {
      "/data": "http://192.168.0.100:8010",
      "/watchlist": "http://192.168.0.100:8010",
      "/action": "http://192.168.0.100:8010",
      "/vms": "http://192.168.0.100:8010",
      "/hunter-aio": "http://192.168.0.100:8010",
      "/health": "http://192.168.0.100:8010",
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          recharts: ["recharts"],
          "react-vendor": ["react", "react-dom", "react-router-dom"],
          tanstack: ["@tanstack/react-query"],
        },
      },
    },
  },
});
