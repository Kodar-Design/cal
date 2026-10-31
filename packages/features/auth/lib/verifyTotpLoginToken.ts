import { jwtVerify } from "jose";

import { WEBSITE_URL } from "@calcom/lib/constants";

/**
 * Verifies the short-lived token that signJwt issues after a user with 2FA enabled
 * passes an identity-provider login (Google/SAML). Returns the email it was issued for,
 * or null when the token is invalid or expired.
 */
export async function verifyTotpLoginToken(token: string): Promise<string | null> {
  if (!process.env.CALENDSO_ENCRYPTION_KEY) return null;
  const secret = new TextEncoder().encode(process.env.CALENDSO_ENCRYPTION_KEY);
  try {
    const { payload } = await jwtVerify(token, secret, {
      issuer: WEBSITE_URL,
      audience: `${WEBSITE_URL}/auth/login`,
      algorithms: ["HS256"],
    });
    return typeof payload.email === "string" ? payload.email : null;
  } catch {
    return null;
  }
}
