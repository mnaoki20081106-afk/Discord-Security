import { describe, expect, it } from "vitest";
import { DEFAULT_SETTINGS } from "../src/db";
import { scoreUrl } from "../src/engine";

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
