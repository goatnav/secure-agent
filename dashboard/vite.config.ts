import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/v1": "http://localhost:8000" } },
  // Avoid pathological Rollup callback analysis in the dashboard's async action handlers.
  // Minification remains enabled; this small demo tolerates retaining unused exports.
  build: { rollupOptions: { treeshake: false } },
});
