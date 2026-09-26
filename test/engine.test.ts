import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS } from "../src/db";
import { scoreUrl } from "../src/engine";
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
