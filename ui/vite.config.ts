import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Absolute asset URLs: the Go server serves dist/ at the root and falls
  // back to index.html for unknown paths, so a relative "./assets" would
  // break on any fallback page below the root.
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // No source maps in the embedded build: they would double the binary's
    // UI weight and CI compares dist/ byte for byte.
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    restoreMocks: true,
  },
});
