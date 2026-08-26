import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // 127.0.0.1, never the NAME: `localhost` resolves to ::1 first and the API is published on
      // the IPv4 loopback only, so every proxied request waits for the IPv6 attempt to time out
      // (measured elsewhere in this project at ~2 s a request against 5 ms). See CLAUDE.md,
      // "Never address this app as localhost".
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
  build: { outDir: 'dist', sourcemap: false },
});
