import { readFileSync } from 'node:fs';
import { defineConfig, type Plugin } from 'vitest/config';
import react from '@vitejs/plugin-react';

// The Plex fonts are OFL-1.1, which requires the licence to travel with
// the font files. Vite copies the fonts into dist/assets/ because the CSS
// references them, but nothing references OFL.txt, so it is emitted here
// beside them under a fixed name the Go embed test can find.
function fontLicence(): Plugin {
  return {
    name: 'blastgate-font-licence',
    apply: 'build',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'assets/OFL.txt',
        source: readFileSync(new URL('./src/fonts/OFL.txt', import.meta.url)),
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), fontLicence()],
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
    // Never inline a font as a data: URL: the CSP has no font-src
    // exception, so an inlined font is silently blocked and the page falls
    // back to system faces. Other assets keep Vite's default threshold.
    assetsInlineLimit: (file) => (file.endsWith('.woff2') ? false : undefined),
    // Explicit, because the Go server and embed tests expect /assets/.
    assetsDir: 'assets',
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    restoreMocks: true,
  },
});
