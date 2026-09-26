import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { applyTheme, effectiveTheme, getChoice, setChoice } from './theme';

describe('theme', () => {
  beforeEach(() => {
    localStorage.clear();
    delete document.documentElement.dataset.theme;
  });
  afterEach(() => {
    localStorage.clear();
  });

  it('defaults to the system theme', () => {
    expect(getChoice()).toBe('system');
    expect(effectiveTheme('system', true)).toBe('dark');
    expect(effectiveTheme('system', false)).toBe('light');
  });

  it('remembers a manual choice', () => {
    setChoice('light');
    expect(getChoice()).toBe('light');
    // A manual choice wins over the system preference either way.
    expect(effectiveTheme('light', true)).toBe('light');
    expect(effectiveTheme('dark', false)).toBe('dark');
  });

  it('theme survives broken storage', () => {
    localStorage.setItem('blastgate-theme', 'purple');
    expect(getChoice()).toBe('system');

    // Safari private mode and locked-down profiles throw on any storage
    // access; the console must still render, just without memory.
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('SecurityError');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError');
    });
    expect(getChoice()).toBe('system');
    expect(() => setChoice('dark')).not.toThrow();
  });

  it('applyTheme sets the data attribute', () => {
    applyTheme('light');
    expect(document.documentElement.dataset.theme).toBe('light');
    applyTheme('dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
  });
});
