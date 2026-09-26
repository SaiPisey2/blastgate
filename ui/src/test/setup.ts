import { afterEach } from 'vitest';
import { configure } from '@testing-library/react';
import { resetAnnouncer } from '../components/Shell';
import { installMatchMedia, resetMedia } from './media';

// findBy and waitFor give up after 1s by default; a cold, loaded run
// (the first one after npm ci) can take longer than that to settle a
// fetch and a render, and fail a test that is not wrong.
configure({ asyncUtilTimeout: 3000 });

// Installed for every test file, not per test: a component that reads a
// breakpoint must not throw just because its test forgot to mock one.
installMatchMedia();

afterEach(() => {
  resetMedia();
  // The announcer's store is module state and outlives any one test.
  resetAnnouncer();
});
