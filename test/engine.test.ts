import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS, maintenanceScopeAllows } from "../src/db";
import { classifyAuditAction, scoreUrl } from "../src/engine";
import {
  buildLockdownOverwrites,
  dangerousPermissionAdded
} from "../src/discord";

describe("URL risk scoring", () => {
  it("allows explicitly trusted Discord domains", () => {
    expect(scoreUrl(new URL("https://discord.com/channels/@me"), DEFAULT_SETTINGS)).toBe(0);
  });

  it("flags a punycode brand-lookalike URL", () => {
    const score = scoreUrl(
      new URL("https://xn--dscord-nza.example/login/discord/nitro"),
      DEFAULT_SETTINGS
    );
    expect(score).toBeGreaterThanOrEqual(50);
  });

  it("flags explicitly blocked domains", () => {
    const settings = {
      ...DEFAULT_SETTINGS,
      blockedDomains: ["evil.example"]
    };
    expect(scoreUrl(new URL("https://sub.evil.example/path"), settings)).toBe(100);
  });
});


describe("lockdown permissions", () => {
  it("clears explicit allows and adds denies for role/member overwrites", () => {
    const sendMessages = 1n << 11n;
    const connect = 1n << 20n;
    const result = buildLockdownOverwrites("100", [
      { id: "200", type: 0, allow: sendMessages.toString(), deny: "0" },
      { id: "300", type: 1, allow: connect.toString(), deny: "0" }
    ]);

    const role = result.find(item => item.id === "200")!;
    const member = result.find(item => item.id === "300")!;
    const everyone = result.find(item => item.id === "100" && item.type === 0)!;

    expect(BigInt(role.allow) & sendMessages).toBe(0n);
    expect(BigInt(role.deny) & sendMessages).toBe(sendMessages);
    expect(BigInt(member.allow) & connect).toBe(0n);
    expect(BigInt(member.deny) & connect).toBe(connect);
    expect(BigInt(everyone.deny) & sendMessages).toBe(sendMessages);
  });
});

describe("dangerous permission detection", () => {
  it("detects newly granted Administrator", () => {
    expect(dangerousPermissionAdded("0", (1n << 3n).toString())).toBe(true);
  });

  it("does not flag permission removal", () => {
    expect(dangerousPermissionAdded((1n << 3n).toString(), "0")).toBe(false);
  });
});


describe("lockdown safety", () => {
  it("preserves unrelated permission bits while blocking dangerous activity", () => {
    const viewChannel = 1n << 10n;
    const sendMessages = 1n << 11n;
    const result = buildLockdownOverwrites("100", [
      {
        id: "200",
        type: 0,
        allow: (viewChannel | sendMessages).toString(),
        deny: "0"
      }
    ]);
    const role = result.find(item => item.id === "200")!;
    expect(BigInt(role.allow) & viewChannel).toBe(viewChannel);
    expect(BigInt(role.allow) & sendMessages).toBe(0n);
  });

  it("does not duplicate an existing everyone overwrite", () => {
    const result = buildLockdownOverwrites("100", [
      { id: "100", type: 0, allow: "0", deny: "0" }
    ]);
    expect(result.filter(item => item.id === "100" && item.type === 0)).toHaveLength(1);
  });
});

describe("URL allowlist safety", () => {
  it("allows subdomains of explicitly allowed domains", () => {
    const settings = {
      ...DEFAULT_SETTINGS,
      allowedDomains: ["example.com"],
      blockedDomains: []
    };
    expect(scoreUrl(new URL("https://login.example.com/account"), settings)).toBe(0);
  });

  it("raises risk for URLs containing embedded credentials", () => {
    const score = scoreUrl(
      new URL("https://discord-login:secret@evil.example/verify/nitro"),
      DEFAULT_SETTINGS
    );
    expect(score).toBeGreaterThanOrEqual(50);
  });
});


describe("security threshold defaults", () => {
  it("covers channel overwrite tampering", () => {
    expect(DEFAULT_SETTINGS.thresholds.channelOverwrite).toBeGreaterThan(0);
  });

  it("sets a member-prune containment threshold", () => {
    expect(DEFAULT_SETTINGS.thresholds.memberPrune).toBeGreaterThanOrEqual(1);
  });
});


describe("managed service bot model", () => {
  it("does not rely on globally trusting the Main Bot actor", () => {
    expect(DEFAULT_SETTINGS.trustedUserIds).toEqual([]);
    expect(DEFAULT_SETTINGS.allowedBotIds).toEqual([]);
  });
});


describe("maximum protection policy", () => {
  it("keeps dangerous-permission checks independent of capability diagnostics", () => {
    expect(dangerousPermissionAdded("0", (1n << 28n).toString())).toBe(true);
  });
});


describe("Main Bot trust boundary", () => {
  it("keeps Main out of the default trusted actor list", () => {
    expect(DEFAULT_SETTINGS.trustedUserIds).not.toContain("main-bot");
  });
});


describe("Discord audit action coverage", () => {
  it("maps destructive and privilege-sensitive audit actions", () => {
    expect(classifyAuditAction(12)).toBe("channel_delete");
    expect(classifyAuditAction(13)).toBe("channel_overwrite");
    expect(classifyAuditAction(15)).toBe("channel_overwrite");
    expect(classifyAuditAction(21)).toBe("member_prune");
    expect(classifyAuditAction(28)).toBe("bot_add");
    expect(classifyAuditAction(32)).toBe("role_delete");
    expect(classifyAuditAction(50)).toBe("webhook");
    expect(classifyAuditAction(142)).toBe("automod_change");
  });

  it("ignores unsupported audit actions instead of inventing enforcement", () => {
    expect(classifyAuditAction(9999)).toBeNull();
  });
});

describe("URL allowlist boundary", () => {
  it("does not trust lookalike parent domains", () => {
    expect(scoreUrl(
      new URL("https://discord.com.evil.example/login/nitro"),
      DEFAULT_SETTINGS
    )).toBeGreaterThanOrEqual(50);
  });
});


describe("Safety Baseline defaults", () => {
  it("enforces Discord explicit-media scanning for all members by default", () => {
    expect(DEFAULT_SETTINGS.safety.enforceExplicitContentFilter).toBe(true);
  });

  it("uses at least Medium verification by default", () => {
    expect(DEFAULT_SETTINGS.safety.minimumVerificationLevel).toBeGreaterThanOrEqual(2);
  });
});


describe("maintenance lease scope", () => {
  it("allows only restore actions needed by the backup pipeline", () => {
    for (const action of [
      "channel_create",
      "channel_update",
      "channel_overwrite",
      "role_create",
      "role_update",
      "permission_escalation",
      "ban_add",
      "automod_change",
      "guild_update"
    ]) {
      expect(maintenanceScopeAllows("restore", action)).toBe(true);
    }
  });

  it("does not turn restore into a broad Security bypass", () => {
    for (const action of [
      "channel_delete",
      "role_delete",
      "webhook",
      "bot_add",
      "member_prune",
      "kick",
      "integration_change"
    ]) {
      expect(maintenanceScopeAllows("restore", action)).toBe(false);
    }
  });

  it("keeps explicit all-scope available for emergency administration", () => {
    expect(maintenanceScopeAllows("all", "bot_add")).toBe(true);
  });
});


describe("URL policy precedence", () => {
  it("lets an explicit block override an allow entry for the same domain", () => {
    const settings = {
      ...DEFAULT_SETTINGS,
      allowedDomains: ["example.com"],
      blockedDomains: ["example.com"]
    };
    expect(scoreUrl(new URL("https://example.com/login"), settings)).toBe(100);
  });

  it("lets a blocked parent domain cover its subdomains", () => {
    const settings = {
      ...DEFAULT_SETTINGS,
      allowedDomains: [],
      blockedDomains: ["evil.example"]
    };
    expect(scoreUrl(new URL("https://cdn.evil.example/file"), settings)).toBe(100);
  });
});


describe("coordinated content defaults", () => {
  it("requires multiple distinct actors before server-wide containment", () => {
    expect(DEFAULT_SETTINGS.thresholds.severeContentUsers).toBeGreaterThanOrEqual(2);
  });

  it("uses a short burst window for coordinated phishing or malware attacks", () => {
    expect(DEFAULT_SETTINGS.thresholds.severeContentWindowSeconds).toBeGreaterThanOrEqual(5);
    expect(DEFAULT_SETTINGS.thresholds.severeContentWindowSeconds).toBeLessThanOrEqual(300);
  });
});
