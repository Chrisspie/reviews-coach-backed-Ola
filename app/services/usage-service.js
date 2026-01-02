import { getUsageBucket as ensureUsageBucket, quotaSnapshot as quotaSnapshotForLimit } from '../../lib/quota.js';

export function createUsageService({ FREE_DAILY_LIMIT }) {
  const usageCounters = new Map();

  const getUsageBucket = (key) => ensureUsageBucket(usageCounters, key);
  const quotaSnapshot = (bucket) => quotaSnapshotForLimit(FREE_DAILY_LIMIT, bucket);
  const resetUsage = (userId) => {
    if (!userId) return;
    usageCounters.delete(userId);
  };

  return {
    usageCounters,
    getUsageBucket,
    quotaSnapshot,
    resetUsage,
    freeDailyLimit: FREE_DAILY_LIMIT
  };
}
