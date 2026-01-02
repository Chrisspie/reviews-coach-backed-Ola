export function clientIp(req) {
  if (!req) return '';
  return (req.headers?.['x-forwarded-for'] || req.ip || '')
    .toString()
    .split(',')[0]
    .trim();
}
