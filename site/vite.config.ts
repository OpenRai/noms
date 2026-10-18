import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  base: '/noms/',
  build: {
    outDir: '../site-dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        playground: fileURLToPath(new URL('index.html', import.meta.url)),
        conformance: fileURLToPath(new URL('conformance.html', import.meta.url)),
      },
      output: { manualChunks: (id) => id.includes('@noble/') || id.includes('/typescript/dist/') ? 'noms-crypto' : undefined },
    },
  },
});
