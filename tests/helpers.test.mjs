import { describe, it, expect, vi, afterEach } from 'vitest';

import { createLicenseVerifier, constantTimeCompare } from '../lib/licenses.mjs';
import { getUsageBucket, quotaSnapshot } from '../lib/quota.mjs';
import { maskContents, usageFrom, setUsageHeaders } from '../lib/gemini.mjs';
import { clientIp } from '../lib/request.mjs';
import { sha256Buffer } from '../config.mjs';

afterEach(() => {
  vi.useRealTimers();
});

describe('license helpers', () => {
  it('compares buffers in constant time and respects length', () => {
    const a = Buffer.from('abc');
    const b = Buffer.from('abc');
    const c = Buffer.from('abcd');
    expect(constantTimeCompare(a, b)).toBe(true);
    expect(constantTimeCompare(a, c)).toBe(false);
    expect(constantTimeCompare(a, Buffer.from('abd'))).toBe(false);
  });

  it('verifies hashed license entries only when enabled', () => {
    const records = [{ id: 'pro', hash: sha256Buffer('secret-key') }];
    const disabled = createLicenseVerifier(records, false);
    expect(disabled('secret-key')).toBeNull();

    const verify = createLicenseVerifier(records, true);
    expect(verify('secret-key')).toEqual(records[0]);
    expect(verify('other')).toBeNull();
  });
});

describe('quota helpers', () => {
  it('resets usage buckets when the date changes', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    const store = new Map();
    const first = getUsageBucket(store, 'user-1');
    first.count = 5;

    vi.setSystemTime(new Date('2024-01-02T00:00:00Z'));
    const second = getUsageBucket(store, 'user-1');
    expect(second).not.toBe(first);
    expect(second.count).toBe(0);
  });

  it('produces quota snapshots only when limit is configured', () => {
    expect(quotaSnapshot(0, { count: 1 })).toBeNull();
    const snapshot = quotaSnapshot(5, { count: 2 });
    expect(snapshot).toEqual({ limit: 5, remaining: 3 });
  });
});

describe('gemini helpers', () => {
  it('masks and truncates prompt contents safely', () => {
    expect(maskContents(null)).toBe('[invalid-contents]');
    expect(maskContents([{ parts: [{}] }])).toBe('[no-text]');
    const short = maskContents([{ parts: [{ text: 'hello' }] }]);
    expect(short).toBe('hello');
    const longText = 'a'.repeat(150);
    const masked = maskContents([{ parts: [{ text: longText }] }]);
    expect(masked.endsWith('...')).toBe(true);
    expect(masked.length).toBeLessThanOrEqual(123);
  });

  it('extracts usage metadata from different response shapes', () => {
    const usageMetadata = usageFrom({ usageMetadata: { totalTokenCount: 10, promptTokenCount: 4, candidatesTokenCount: 6 } });
    expect(usageMetadata).toMatchObject({ total: 10, input: 4, output: 6 });
    const usageFallback = usageFrom({ usage: { total_tokens: 8, prompt_tokens: 3, completion_tokens: 5 } });
    expect(usageFallback).toMatchObject({ total: 8, input: 3, output: 5 });
    expect(usageFrom(null)).toBeNull();
  });

  it('sets token usage headers only when values are present', () => {
    const headers = new Map();
    const reply = {
      header: (key, value) => {
        headers.set(key, value);
        return reply;
      }
    };
    setUsageHeaders(reply, { total: 10, input: 5, input_cached: 1, output: 5, reasoning: 0 });
    expect(headers.get('X-Token-Usage-Total')).toBe('10');
    expect(headers.get('X-Token-Usage-Input')).toBe('5');
    expect(headers.get('X-Token-Usage-Input-Cached')).toBe('1');
    expect(headers.get('X-Token-Usage-Output')).toBe('5');
    expect(headers.get('X-Token-Usage-Reasoning')).toBe('0');
  });
});

describe('request helpers', () => {
  it('extracts the first IP from headers or falls back to req.ip', () => {
    expect(clientIp({ headers: { 'x-forwarded-for': '10.0.0.1, 2.2.2.2' } })).toBe('10.0.0.1');
    expect(clientIp({ headers: {}, ip: '127.0.0.1' })).toBe('127.0.0.1');
    expect(clientIp(null)).toBe('');
  });
});
