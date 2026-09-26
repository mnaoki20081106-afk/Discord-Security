import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS, maintenanceScopeAllows } from "../src/db";
import { classifyAuditAction, fetchAuditBacklog, scoreUrl } from "../src/engine";
import { OrderedTaskLanes } from "../src/gateway";
import {
  buildLockdownOverwrites,
  dangerousPermissionAdded,
  patchChannelOverwrites
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


describe("lockdown Discord API error handling", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("rejects a non-2xx permission overwrite response instead of reporting success", async () => {
    vi.stubGlobal("fetch", async () =>
      new Response('{"message":"Missing Permissions"}', {
        status: 403,
        headers: { "Content-Type": "application/json" }
      })
    );

    await expect(
      patchChannelOverwrites(
        { DISCORD_BOT_TOKEN: "test-token" } as never,
        "123",
        [{ id: "456", type: 0, allow: "0", deny: "2048" }],
        "test lockdown"
      )
    ).rejects.toMatchObject({ status: 403 });
  });
});


describe("audit backlog pagination", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("paginates until the stored audit cursor is found", async () => {
    const first = Array.from({ length: 100 }, (_, index) => ({
      id: String(3000 - index),
      guild_id: "123",
      action_type: 12,
      user_id: "999"
    }));
    const second = [
      { id: "2000", guild_id: "123", action_type: 32, user_id: "999" },
      { id: "cursor", guild_id: "123", action_type: 1, user_id: "999" }
    ];
    const calls: string[] = [];

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      calls.push(url.toString());
      return Response.json({
        audit_log_entries: calls.length === 1 ? first : second
      });
    });

    const backlog = await fetchAuditBacklog(
      { DISCORD_BOT_TOKEN: "test-token" } as never,
      "123",
      "cursor",
      10
    );

    expect(backlog.cursorFound).toBe(true);
    expect(backlog.truncated).toBe(false);
    expect(backlog.pages).toBe(2);
    expect(backlog.entries).toHaveLength(101);
    expect(new URL(calls[1]!).searchParams.get("before")).toBe("2901");
  });


  it("marks a partial pagination API failure without calling it overflow", async () => {
    let call = 0;
    vi.stubGlobal("fetch", async () => {
      call += 1;
      if (call === 1) {
        return Response.json({
          audit_log_entries: Array.from({ length: 100 }, (_, index) => ({
            id: String(8000 - index),
            guild_id: "123",
            action_type: 12,
            user_id: "999"
          }))
        });
      }
      return Response.json(
        { message: "temporary audit API failure" },
        { status: 500 }
      );
    });

    const backlog = await fetchAuditBacklog(
      { DISCORD_BOT_TOKEN: "test-token" } as never,
      "123",
      "older-cursor",
      10
    );

    expect(backlog.pages).toBe(1);
    expect(backlog.entries).toHaveLength(100);
    expect(backlog.cursorFound).toBe(false);
    expect(backlog.fetchFailed).toBe(true);
    expect(backlog.truncated).toBe(false);
  });

  it("marks a full page backlog as truncated when the cursor is still not found", async () => {
    let page = 0;
    vi.stubGlobal("fetch", async () => {
      const start = 5000 - page++ * 100;
      return Response.json({
        audit_log_entries: Array.from({ length: 100 }, (_, index) => ({
          id: String(start - index),
          guild_id: "123",
          action_type: 12,
          user_id: "999"
        }))
      });
    });

    const backlog = await fetchAuditBacklog(
      { DISCORD_BOT_TOKEN: "test-token" } as never,
      "123",
      "missing-cursor",
      3
    );

    expect(backlog.cursorFound).toBe(false);
    expect(backlog.truncated).toBe(true);
    expect(backlog.pages).toBe(3);
    expect(backlog.entries).toHaveLength(300);
  });
});


describe("Gateway Security event lanes", () => {
  it("preserves order inside the same lane", async () => {
    const errors: unknown[] = [];
    const lanes = new OrderedTaskLanes((_label, error) => errors.push(error));
    const order: string[] = [];
    let release!: () => void;
    const blocker = new Promise<void>(resolve => {
      release = resolve;
    });

    lanes.enqueue("audit:1", "first", async () => {
      order.push("first-start");
      await blocker;
      order.push("first-end");
    });
    lanes.enqueue("audit:1", "second", async () => {
      order.push("second");
    });

    await Promise.resolve();
    expect(order).toEqual(["first-start"]);

    release();
    await lanes.waitForLane("audit:1");
    expect(order).toEqual(["first-start", "first-end", "second"]);
    expect(errors).toEqual([]);
  });

  it("allows audit work to bypass a blocked message lane", async () => {
    const errors: unknown[] = [];
    const lanes = new OrderedTaskLanes((_label, error) => errors.push(error));
    let releaseMessage!: () => void;
    const messageBlocker = new Promise<void>(resolve => {
      releaseMessage = resolve;
    });
    let messageFinished = false;
    let auditFinished = false;

    lanes.enqueue("message:1", "message", async () => {
      await messageBlocker;
      messageFinished = true;
    });
    lanes.enqueue("audit:1", "audit", async () => {
      auditFinished = true;
    });

    await lanes.waitForLane("audit:1");
    expect(auditFinished).toBe(true);
    expect(messageFinished).toBe(false);

    releaseMessage();
    await lanes.waitForLane("message:1");
    expect(messageFinished).toBe(true);
    expect(errors).toEqual([]);
  });

  it("isolates work across guilds", async () => {
    const lanes = new OrderedTaskLanes(() => undefined);
    let releaseGuildA!: () => void;
    const guildABlocker = new Promise<void>(resolve => {
      releaseGuildA = resolve;
    });
    let guildBDone = false;

    lanes.enqueue("audit:guild-a", "guild-a", async () => {
      await guildABlocker;
    });
    lanes.enqueue("audit:guild-b", "guild-b", async () => {
      guildBDone = true;
    });

    await lanes.waitForLane("audit:guild-b");
    expect(guildBDone).toBe(true);

    releaseGuildA();
    await lanes.waitForLane("audit:guild-a");
    expect(lanes.pendingLaneCount()).toBe(0);
  });
});
