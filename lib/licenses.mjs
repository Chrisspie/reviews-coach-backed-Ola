import { timingSafeEqual } from 'node:crypto';
import { stripQuotes, sha256Buffer } from '../config.mjs';

export function constantTimeCompare(bufA, bufB) {
  if (!bufA || !bufB || bufA.length !== bufB.length) return false;
  try {
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

export function createLicenseVerifier(records = [], hasLicenses = false) {
  return function verifyLicenseKey(candidate) {
    if (!candidate || !hasLicenses) return null;
    const normalized = stripQuotes(candidate);
    if (!normalized) return null;
    const hashed = sha256Buffer(normalized);
    for (const record of records) {
      if (constantTimeCompare(hashed, record.hash)) {
        return record;
      }
    }
    return null;
  };
}
