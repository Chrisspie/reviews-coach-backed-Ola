import { SignJWT, jwtVerify } from 'jose';

export function createJwtService({ authSecret, defaultTtlSeconds }) {
  const enc = new TextEncoder();
  const jwtKey = enc.encode(authSecret);
  const issuer = 'reviews-coach-proxy';

  async function signJwt(payload, ttlSec = defaultTtlSeconds) {
    const now = Math.floor(Date.now() / 1000);
    return await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(now)
      .setIssuer(issuer)
      .setAudience(issuer)
      .setExpirationTime(now + ttlSec)
      .sign(jwtKey);
  }

  async function verifyJwt(token) {
    const { payload } = await jwtVerify(token, jwtKey, {
      issuer,
      audience: issuer
    });
    return payload;
  }

  return { signJwt, verifyJwt };
}
