import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openStream, setStreamStatus, streamStatus } from './api';
import { mockFetch } from './test/fetch';

// FakeES stands in for the browser's EventSource. refuse() is what the
// browser does on a non-2xx answer (the stream's 429 for a fifth tab, or a
// 401): readyState CLOSED, one error event, and no retry of its own.
class FakeES {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  static all: FakeES[] = [];
  readyState = FakeES.CONNECTING;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    FakeES.all.push(this);
  }
  addEventListener() {}
  close() {
    this.readyState = FakeES.CLOSED;
  }
  open() {
    this.readyState = FakeES.OPEN;
    this.onopen?.();
  }
  refuse() {
    this.readyState = FakeES.CLOSED;
    this.onerror?.();
  }
}

const opened = () => FakeES.all.length;
const latest = () => FakeES.all[FakeES.all.length - 1];

beforeEach(() => {
  FakeES.all = [];
  vi.stubGlobal('EventSource', FakeES);
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  setStreamStatus('offline');
});

describe('live stream', () => {
  it('a refused stream with a live session says too many tabs and retries with backoff', async () => {
    mockFetch({ 'GET /api/me': { body: { name: 'bob', csrf: 'c' } } });
    const close = openStream();
    expect(opened()).toBe(1);
    latest().refuse();
    await vi.advanceTimersByTimeAsync(0);
    expect(streamStatus()).toBe('limited');

    // 5s, then 10s, then 20s: a tab that keeps being refused backs off.
    for (const wait of [5000, 10000, 20000]) {
      const before = opened();
      await vi.advanceTimersByTimeAsync(wait - 1);
      expect(opened()).toBe(before);
      await vi.advanceTimersByTimeAsync(1);
      expect(opened()).toBe(before + 1);
      latest().refuse();
      await vi.advanceTimersByTimeAsync(0);
      expect(streamStatus()).toBe('limited');
    }
    // It never waits longer than a minute.
    await vi.advanceTimersByTimeAsync(40000);
    latest().refuse();
    await vi.advanceTimersByTimeAsync(0);
    const before = opened();
    await vi.advanceTimersByTimeAsync(60000);
    expect(opened()).toBe(before + 1);

    // Once a slot frees up it is live, and the backoff starts over.
    latest().open();
    expect(streamStatus()).toBe('live');
    latest().refuse();
    await vi.advanceTimersByTimeAsync(5000);
    expect(opened()).toBe(before + 2);

    // Closing (sign-out, leaving the app) cancels a pending retry.
    latest().refuse();
    await vi.advanceTimersByTimeAsync(0);
    close();
    await vi.advanceTimersByTimeAsync(120000);
    expect(opened()).toBe(before + 2);
    expect(streamStatus()).toBe('offline');
  });

  it('closing while the session check is still out schedules nothing', async () => {
    mockFetch({ 'GET /api/me': { body: { name: 'bob', csrf: 'c' } } });
    const close = openStream();
    latest().refuse();
    // Signed out or navigated away before /api/me answered.
    close();
    await vi.advanceTimersByTimeAsync(120000);
    expect(opened()).toBe(1);
    expect(streamStatus()).toBe('offline');
  });

  it('a refused stream with a dead session signs out and does not retry', async () => {
    mockFetch({ 'GET /api/me': { status: 401, body: { error: 'unauthorized' } } });
    openStream();
    latest().refuse();
    await vi.advanceTimersByTimeAsync(120000);
    expect(opened()).toBe(1);
    expect(streamStatus()).toBe('offline');
    expect(window.location.hash).toBe('#/login');
  });
});
