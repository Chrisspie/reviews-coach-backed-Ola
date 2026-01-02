export function getUsageBucket(store, key) {
  if (!store || !key) return null;
  const today = new Date().toISOString().slice(0, 10);
  let bucket = store.get(key);
  if (!bucket || bucket.date !== today) {
    bucket = { date: today, count: 0 };
    store.set(key, bucket);
  }
  return bucket;
}

export function quotaSnapshot(limit, bucket) {
  if (!bucket || !limit) return null;
  const remaining = Math.max(0, limit - bucket.count);
  return { limit, remaining };
}
