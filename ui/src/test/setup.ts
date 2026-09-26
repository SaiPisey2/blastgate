import { afterEach } from 'vitest';
import { installMatchMedia, resetMedia } from './media';

// Installed for every test file, not per test: a component that reads a
// breakpoint must not throw just because its test forgot to mock one.
installMatchMedia();

afterEach(() => {
  resetMedia();
});
