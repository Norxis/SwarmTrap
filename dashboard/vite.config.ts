import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/dashboard/",
  server: {
    proxy: {
      "/dashboard/data": {
        target: "http://192.168.0.100:8010",
        rewrite: (path: string) => path.replace(/^\/dashboard/, ""),
      },
      "/dashboard/health": {
        target: "http://192.168.0.100:8010",
        rewrite: (path: string) => path.replace(/^\/dashboard/, ""),
      },
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
