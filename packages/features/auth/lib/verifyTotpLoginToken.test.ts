// @vitest-environment node
import { SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { WEBSITE_URL } from "@calcom/lib/constants";

import signJwt from "./signJwt";
import { verifyTotpLoginToken } from "./verifyTotpLoginToken";

const KEY = "k".repeat(32);

describe("verifyTotpLoginToken", () => {
  const originalKey = process.env.CALENDSO_ENCRYPTION_KEY;

  beforeEach(() => {
    process.env.CALENDSO_ENCRYPTION_KEY = KEY;
  });

  afterEach(() => {
    process.env.CALENDSO_ENCRYPTION_KEY = originalKey;
  });

  it("returns the email of a token from signJwt", async () => {
    const token = await signJwt({ email: "jan@example.com" });
    await expect(verifyTotpLoginToken(token)).resolves.toBe("jan@example.com");
  });

  it("returns null for a token signed with another key", async () => {
    const token = await new SignJWT({ email: "jan@example.com" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(WEBSITE_URL)
      .setAudience(`${WEBSITE_URL}/auth/login`)
      .setExpirationTime("2m")
      .sign(new TextEncoder().encode("x".repeat(32)));
    await expect(verifyTotpLoginToken(token)).resolves.toBeNull();
  });

  it("returns null for an expired token", async () => {
    const token = await new SignJWT({ email: "jan@example.com" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer(WEBSITE_URL)
      .setAudience(`${WEBSITE_URL}/auth/login`)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(new TextEncoder().encode(KEY));
    await expect(verifyTotpLoginToken(token)).resolves.toBeNull();
  });

  it("returns null for garbage", async () => {
    await expect(verifyTotpLoginToken("not-a-jwt")).resolves.toBeNull();
  });

  it("returns null when the encryption key is missing", async () => {
    const token = await signJwt({ email: "jan@example.com" });
    delete process.env.CALENDSO_ENCRYPTION_KEY;
    await expect(verifyTotpLoginToken(token)).resolves.toBeNull();
  });
});
