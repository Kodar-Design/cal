import type { User } from "next-auth";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { IdentityProvider, UserPermissionRole } from "@calcom/prisma/enums";

import { ErrorCode } from "./ErrorCode";

// Mock dependencies
vi.mock("@calcom/prisma", () => ({
  prisma: {
    user: {
      update: vi.fn(),
    },
  },
  default: {
    user: {
      update: vi.fn(),
    },
  },
}));

const mockFindByEmailAndIncludeProfilesAndPassword = vi.fn();

vi.mock("@calcom/features/users/repositories/UserRepository", () => {
  return {
    UserRepository: vi.fn().mockImplementation(function () {
      return {
        findByEmailAndIncludeProfilesAndPassword: mockFindByEmailAndIncludeProfilesAndPassword,
      };
    }),
  };
});

vi.mock("./verifyPassword", () => ({
  verifyPassword: vi.fn(),
}));

vi.mock("@calcom/lib/checkRateLimitAndThrowError", () => ({
  checkRateLimitAndThrowError: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@calcom/lib/server/PiiHasher", () => ({
  hashEmail: vi.fn((email: string) => `hashed_${email}`),
}));

vi.mock("@calcom/lib/totp", () => ({
  totpAuthenticatorCheck: vi.fn(),
}));

vi.mock("./verifyTotpLoginToken", () => ({
  verifyTotpLoginToken: vi.fn(),
}));

vi.mock("@calcom/lib/crypto", () => ({
  symmetricDecrypt: vi.fn(),
  symmetricEncrypt: vi.fn(),
}));

vi.mock("@calcom/lib/auth/isPasswordValid", () => ({
  isPasswordValid: vi.fn(),
}));

vi.mock("@calcom/lib/env", () => ({
  isENVDev: false,
}));

vi.mock("@calcom/lib/constants", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@calcom/lib/constants")>();
  return {
    ...actual,
    IS_TEAM_BILLING_ENABLED: false,
    ENABLE_PROFILE_SWITCHER: false,
    WEBAPP_URL: "http://localhost:3000",
  };
});

vi.mock("@calcom/lib/logger", () => ({
  default: {
    getSubLogger: vi.fn(() => ({
      debug: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
    })),
  },
}));

vi.mock("@calcom/lib/safeStringify", () => ({
  safeStringify: vi.fn((obj) => JSON.stringify(obj)),
}));

vi.mock("./next-auth-custom-adapter", () => ({
  default: vi.fn(() => ({
    linkAccount: vi.fn(),
  })),
}));

vi.mock("@calcom/features/profile/repositories/ProfileRepository", () => ({
  ProfileRepository: {
    findAllProfilesForUserIncludingMovedUser: vi.fn(),
    findByUpIdWithAuth: vi.fn(),
  },
}));

describe("CredentialsProvider authorize", () => {
  let authorizeCredentials: typeof import("./next-auth-options").authorizeCredentials;
  let verifyPassword: any;
  let verifyTotpLoginToken: any;
  let totpAuthenticatorCheck: any;
  let symmetricDecrypt: any;

  beforeEach(async () => {
    vi.clearAllMocks();
    mockFindByEmailAndIncludeProfilesAndPassword.mockReset();

    const verifyPasswordModule = await import("./verifyPassword");
    verifyPassword = verifyPasswordModule.verifyPassword;
    verifyTotpLoginToken = (await import("./verifyTotpLoginToken")).verifyTotpLoginToken;
    totpAuthenticatorCheck = (await import("@calcom/lib/totp")).totpAuthenticatorCheck;
    symmetricDecrypt = (await import("@calcom/lib/crypto")).symmetricDecrypt;

    // Import the exported authorize function directly
    const authModule = await import("./next-auth-options");
    authorizeCredentials = authModule.authorizeCredentials;
  });

  const createMockUser = (overrides: Partial<any> = {}) => ({
    id: 1,
    email: "test@example.com",
    name: "Test User",
    username: "testuser",
    role: UserPermissionRole.USER,
    locked: false,
    identityProvider: IdentityProvider.CAL,
    twoFactorEnabled: false,
    twoFactorSecret: null,
    backupCodes: null,
    password: {
      hash: "$2a$10$hashedpassword",
    },
    allProfiles: [
      {
        id: 1,
        upId: "usr_123",
        username: "testuser",
      },
    ],
    teams: [],
    ...overrides,
  });

  describe("Password validation", () => {
    it("should throw error when user has no password hash with CAL identity provider", async () => {
      const mockUser = createMockUser({
        password: null,
        identityProvider: IdentityProvider.CAL,
      });
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(mockUser);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          password: "password123",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectEmailPassword);
    });

    it("should throw error when user has no password hash with Google identity provider", async () => {
      const mockUser = createMockUser({
        password: null,
        identityProvider: IdentityProvider.GOOGLE,
      });
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(mockUser);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          password: "password123",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectEmailPassword);
    });

    it("should throw error when user has no password hash with SAML identity provider", async () => {
      const mockUser = createMockUser({
        password: null,
        identityProvider: IdentityProvider.SAML,
      });
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(mockUser);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          password: "password123",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectEmailPassword);
    });

    it("should throw error when user has no password hash even with TOTP code provided", async () => {
      const mockUser = createMockUser({
        password: null,
        identityProvider: IdentityProvider.CAL,
      });
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(mockUser);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          password: "password123",
          totpCode: "123456",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectEmailPassword);
    });

    it("should throw error when user has no password hash with Google identity provider and TOTP code", async () => {
      const mockUser = createMockUser({
        password: null,
        identityProvider: IdentityProvider.GOOGLE,
      });
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(mockUser);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          password: "password123",
          totpCode: "123456",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectEmailPassword);
    });

    it("should throw error when user has no password hash with SAML identity provider and TOTP code", async () => {
      const mockUser = createMockUser({
        password: null,
        identityProvider: IdentityProvider.SAML,
      });
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(mockUser);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          password: "password123",
          totpCode: "123456",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectEmailPassword);
    });
  });

  describe("Identity provider login with 2FA", () => {
    const twoFactorUser = (overrides: Partial<any> = {}) =>
      createMockUser({
        password: null,
        identityProvider: IdentityProvider.GOOGLE,
        twoFactorEnabled: true,
        twoFactorSecret: "encrypted-secret",
        ...overrides,
      });

    beforeEach(() => {
      process.env.CALENDSO_ENCRYPTION_KEY = "k".repeat(32);
      symmetricDecrypt.mockReturnValue("s".repeat(32));
    });

    it("logs in with a valid token and TOTP code without a password", async () => {
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(twoFactorUser());
      verifyTotpLoginToken.mockResolvedValue("test@example.com");
      totpAuthenticatorCheck.mockReturnValue(true);

      const user = await authorizeCredentials({
        email: "test@example.com",
        totpCode: "123456",
        totpLoginToken: "signed-token",
      } as any);

      expect(user).toBeTruthy();
      expect(verifyPassword).not.toHaveBeenCalled();
    });

    it("also skips the password for a password user who signed in through the identity provider", async () => {
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(
        twoFactorUser({ password: { hash: "$2a$10$hashedpassword" } })
      );
      verifyTotpLoginToken.mockResolvedValue("test@example.com");
      totpAuthenticatorCheck.mockReturnValue(true);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          totpCode: "123456",
          totpLoginToken: "signed-token",
        } as any)
      ).resolves.toBeTruthy();
      expect(verifyPassword).not.toHaveBeenCalled();
    });

    it("still requires a correct TOTP code with a valid token", async () => {
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(twoFactorUser());
      verifyTotpLoginToken.mockResolvedValue("test@example.com");
      totpAuthenticatorCheck.mockReturnValue(false);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          totpCode: "000000",
          totpLoginToken: "signed-token",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectTwoFactorCode);
    });

    it("rejects an invalid or expired token", async () => {
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(twoFactorUser());
      verifyTotpLoginToken.mockResolvedValue(null);

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          totpCode: "123456",
          totpLoginToken: "bad-token",
        } as any)
      ).rejects.toThrow(ErrorCode.TotpLoginTokenExpired);
    });

    it("rejects a token issued for a different email", async () => {
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(twoFactorUser());
      verifyTotpLoginToken.mockResolvedValue("someone-else@example.com");

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          totpCode: "123456",
          totpLoginToken: "signed-token",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectEmailPassword);
    });

    it("rejects a token for a user without 2FA", async () => {
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(
        twoFactorUser({ twoFactorEnabled: false })
      );
      verifyTotpLoginToken.mockResolvedValue("test@example.com");

      await expect(
        authorizeCredentials({
          email: "test@example.com",
          totpLoginToken: "signed-token",
        } as any)
      ).rejects.toThrow(ErrorCode.IncorrectEmailPassword);
    });

    it("keeps an admin active when signing in through the identity provider with 2FA", async () => {
      mockFindByEmailAndIncludeProfilesAndPassword.mockResolvedValue(
        twoFactorUser({ role: UserPermissionRole.ADMIN, identityProvider: IdentityProvider.CAL })
      );
      verifyTotpLoginToken.mockResolvedValue("test@example.com");
      totpAuthenticatorCheck.mockReturnValue(true);

      const user = (await authorizeCredentials({
        email: "test@example.com",
        totpCode: "123456",
        totpLoginToken: "signed-token",
      } as any)) as any;

      expect(user.role).toBe(UserPermissionRole.ADMIN);
    });
  });
});
