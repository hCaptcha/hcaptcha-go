import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  const extraHosts = env.ALLOWED_HOSTS?.split(",").map((host) => host.trim()).filter(Boolean) ?? [];
  const proxy = {
    "/api": {
      target: env.GO_BACKEND_URL || "http://127.0.0.1:8080",
      changeOrigin: false,
      xfwd: true,
      rewrite: (path: string) => path.replace(/^\/api/, ""),
    },
  };
  const server = {
    host: "127.0.0.1",
    port: 3000,
    strictPort: true,
    allowedHosts: extraHosts,
    proxy,
  };

  return {
    plugins: [react()],
    server,
    preview: server,
  };
});
