import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SETTINGS, maintenanceScopeAllows } from "../src/db";
import {
  auditContainmentDecision,
  auditEntryCreatedAt,
  classifyAuditAction,
  fetchAuditBacklog,
  isSecurityBotSelfTarget,
  isStrongSpam,
  raidConfidence,
  scoreUrl,
  shouldAutoSanctionActor,
  shouldSanctionActor
} from "../src/engine";
import { OrderedTaskLanes } from "../src/gateway";
import { applyBridgeSecurityFloor, isConfiguredMainBot, isManualDashboardLockdown } from "../src/index";
import {
  buildLockdownOverwrites,
  buildManagedBotRecoveryOverwrites,
  dangerousPermissionAdded,
  isHierarchyRelevantDangerousRole,
  patchChannelOverwrites,
  roleIsStrictlyAbove
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

  it("keeps emergency operator roles and members usable during lockdown", () => {
    const sendMessages = 1n << 11n;
    const connect = 1n << 20n;
    const result = buildLockdownOverwrites(
      "100",
      [
        { id: "200", type: 0, allow: "0", deny: sendMessages.toString() },
        { id: "300", type: 1, allow: "0", deny: connect.toString() },
        { id: "400", type: 0, allow: sendMessages.toString(), deny: "0" }
      ],
      { roleIds: ["200"], memberIds: ["300"] }
    );

    const operatorRole = result.find(item => item.id === "200" && item.type === 0)!;
    const operatorMember = result.find(item => item.id === "300" && item.type === 1)!;
    const normalRole = result.find(item => item.id === "400" && item.type === 0)!;

    expect(BigInt(operatorRole.allow) & sendMessages).toBe(sendMessages);
    expect(BigInt(operatorRole.deny) & sendMessages).toBe(0n);
    expect(BigInt(operatorMember.allow) & connect).toBe(connect);
    expect(BigInt(operatorMember.deny) & connect).toBe(0n);
    expect(BigInt(normalRole.deny) & sendMessages).toBe(sendMessages);
  });

  it("adds missing emergency operator overwrites so everyone deny cannot silence them", () => {
    const sendMessages = 1n << 11n;
    const result = buildLockdownOverwrites(
      "100",
      [],
      { roleIds: ["200"], memberIds: ["300"] }
    );

    const everyone = result.find(item => item.id === "100" && item.type === 0)!;
    const operatorRole = result.find(item => item.id === "200" && item.type === 0)!;
    const operatorMember = result.find(item => item.id === "300" && item.type === 1)!;

    expect(BigInt(everyone.deny) & sendMessages).toBe(sendMessages);
    expect(BigInt(operatorRole.allow) & sendMessages).toBe(sendMessages);
    expect(BigInt(operatorMember.allow) & sendMessages).toBe(sendMessages);
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


describe("Security Bot self-install boundary", () => {
  it("never treats the Security Bot's own application ID as an unauthorized bot addition", () => {
    const env = { DISCORD_APPLICATION_ID: "987654321098765432" };
    expect(isSecurityBotSelfTarget(env, "987654321098765432")).toBe(true);
    expect(isSecurityBotSelfTarget(env, "987654321098765433")).toBe(false);
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


describe("Main Bot bridge identity boundary", () => {
  it("accepts only the exact configured Main Bot application ID", () => {
    const env = { MAIN_BOT_APPLICATION_ID: "123456789012345678" };
    expect(isConfiguredMainBot(env, "123456789012345678")).toBe(true);
    expect(isConfiguredMainBot(env, "123456789012345679")).toBe(false);
  });

  it("fails closed when the Main Bot application ID is absent or invalid", () => {
    expect(isConfiguredMainBot({}, "123456789012345678")).toBe(false);
    expect(
      isConfiguredMainBot(
        { MAIN_BOT_APPLICATION_ID: "not-a-discord-id" },
        "not-a-discord-id"
      )
    ).toBe(false);
  });
});


describe("Main bridge protected Security core", () => {
  it("forces the independent protection floor even if Main requests weaker settings", () => {
    const current = structuredClone(DEFAULT_SETTINGS);
    current.trustedUserIds = ["111", "222"];
    current.trustedRoleIds = ["333"];
    current.allowedBotIds = ["444"];
    current.allowedDomains = ["discord.com", "example.com"];

    const patch = applyBridgeSecurityFloor(current, {
      enabled: false,
      mode: "audit",
      modules: {
        ...current.modules,
        antiNuke: false,
        antiRaid: false,
        antiSpam: false,
        antiPhishing: false,
        dangerousAttachments: false,
        botGuard: false,
        webhookGuard: false,
        roleGuard: false,
        permissionGuard: false,
        automodGuard: false,
        guildGuard: false,
        memberGuard: false
      },
      response: {
        ...current.response,
        stripDangerousRoles: false,
        kickMaliciousBots: false,
        autoLockdown: false,
        deleteUnsafeMessages: false,
        quarantineRaidJoins: false
      },
      safety: {
        enforceExplicitContentFilter: false,
        minimumVerificationLevel: 0
      },
      thresholds: {
        ...current.thresholds,
        crossActionScore: 100,
        channelDelete: 30,
        roleDelete: 30,
        botAdd: 10,
        automodChange: 20,
        severeContentUsers: 50
      },
      trustedUserIds: ["111", "999"],
      trustedRoleIds: ["333", "888"],
      allowedBotIds: ["444", "777"],
      allowedDomains: ["discord.com", "evil.example"]
    });

    expect(patch.enabled).toBe(true);
    expect(patch.mode).toBe("enforce");
    expect(patch.modules?.antiNuke).toBe(true);
    expect(patch.modules?.antiRaid).toBe(true);
    expect(patch.modules?.antiSpam).toBe(false);
    expect(patch.modules?.antiPhishing).toBe(true);
    expect(patch.modules?.botGuard).toBe(true);
    expect(patch.modules?.permissionGuard).toBe(true);
    expect(patch.response?.autoLockdown).toBe(true);
    expect(patch.response?.deleteUnsafeMessages).toBe(true);
    expect(patch.safety?.enforceExplicitContentFilter).toBe(true);
    expect(patch.safety?.minimumVerificationLevel).toBeGreaterThanOrEqual(2);
    expect(patch.thresholds?.crossActionScore).toBeLessThanOrEqual(20);
    expect(patch.thresholds?.channelDelete).toBeLessThanOrEqual(3);
    expect(patch.thresholds?.roleDelete).toBeLessThanOrEqual(3);
    expect(patch.thresholds?.botAdd).toBe(1);
    expect(patch.thresholds?.automodChange).toBe(1);
    expect(patch.thresholds?.severeContentUsers).toBeLessThanOrEqual(6);
    expect(patch.trustedUserIds).toEqual(["111"]);
    expect(patch.trustedRoleIds).toEqual(["333"]);
    expect(patch.allowedBotIds).toEqual(["444"]);
    expect(patch.allowedDomains).toEqual(["discord.com"]);
  });

  it("allows existing permanent exceptions to be removed", () => {
    const current = structuredClone(DEFAULT_SETTINGS);
    current.trustedUserIds = ["111", "222"];
    const patch = applyBridgeSecurityFloor(current, {
      trustedUserIds: ["222"]
    });
    expect(patch.trustedUserIds).toEqual(["222"]);
  });
});

describe("Main dashboard lockdown boundary", () => {
  it("allows Main to unlock only the lockdown it manually started", () => {
    expect(isManualDashboardLockdown("manual dashboard lockdown")).toBe(true);
    expect(isManualDashboardLockdown("channel_delete by attacker")).toBe(false);
    expect(isManualDashboardLockdown("audit backlog overflow")).toBe(false);
    expect(isManualDashboardLockdown(null)).toBe(false);
  });
});


describe("Security role hierarchy safety", () => {
  it("requires Security to be strictly above dangerous roles", () => {
    expect(roleIsStrictlyAbove({ position: 10 }, { position: 9 })).toBe(true);
    expect(roleIsStrictlyAbove({ position: 10 }, { position: 10 })).toBe(false);
    expect(roleIsStrictlyAbove({ position: 9 }, { position: 10 })).toBe(false);
  });
});

describe("managed-bot hierarchy compatibility", () => {
  it("does not treat managed bot roles as removable hierarchy threats", () => {
    const selfRoles = new Set(["security-role"]);
    expect(isHierarchyRelevantDangerousRole({
      id:"main-bot-role",
      permissions:(1n<<3n).toString(),
      managed:true
    }, selfRoles)).toBe(false);
    expect(isHierarchyRelevantDangerousRole({
      id:"human-admin-role",
      permissions:(1n<<3n).toString(),
      managed:false
    }, selfRoles)).toBe(true);
  });

  it("uses the snowflake tie-breaker when Discord reports equal positions", () => {
    expect(roleIsStrictlyAbove(
      {position:10,id:"100"},
      {position:10,id:"200"}
    )).toBe(true);
    expect(roleIsStrictlyAbove(
      {position:10,id:"200"},
      {position:10,id:"100"}
    )).toBe(false);
  });
});

describe("audit entry time", () => {
  it("derives the Discord action time from the audit-entry snowflake", () => {
    const actionAt = Date.UTC(2026, 8, 26, 10, 31, 0, 123);
    const snowflake = ((BigInt(actionAt - 1420070400000) << 22n) + 7n).toString();
    expect(auditEntryCreatedAt(snowflake)).toBe(actionAt);
    expect(auditEntryCreatedAt("not-a-snowflake")).toBeNull();
  });
});

describe("actor auto-sanction confidence", () => {
  it("does not punish ordinary destructive admin bursts", () => {
    expect(shouldAutoSanctionActor({
      action:"channel_delete",
      count:5,
      thresholdValue:2,
      crossActionScore:35,
      crossActionThreshold:12,
      destructiveKinds:1
    })).toBe(false);
    expect(shouldAutoSanctionActor({
      action:"kick",
      count:8,
      thresholdValue:5,
      crossActionScore:32,
      crossActionThreshold:12,
      destructiveKinds:1
    })).toBe(false);
  });

  it("actor sanctions require extreme evidence", () => {
    expect(shouldAutoSanctionActor({
      action:"channel_delete",
      count:10,
      thresholdValue:2,
      crossActionScore:70,
      crossActionThreshold:12,
      destructiveKinds:1
    })).toBe(true);
    expect(shouldAutoSanctionActor({
      action:"role_delete",
      count:1,
      thresholdValue:2,
      crossActionScore:30,
      crossActionThreshold:12,
      destructiveKinds:3
    })).toBe(true);
  });

  it("never auto-sanctions actors for reversible configuration changes", () => {
    expect(shouldAutoSanctionActor({
      action:"channel_overwrite",
      count:100,
      thresholdValue:4,
      crossActionScore:100,
      crossActionThreshold:12,
      destructiveKinds:3
    })).toBe(false);
    expect(shouldAutoSanctionActor({
      action:"permission_escalation",
      count:100,
      thresholdValue:1,
      crossActionScore:100,
      crossActionThreshold:12,
      destructiveKinds:3
    })).toBe(false);
  });
});

describe("actor sanction safety boundary", () => {
  it("destructive audit actions are the only actor-sanctioning class", () => {
    expect(shouldSanctionActor("channel_delete")).toBe(true);
    expect(shouldSanctionActor("role_delete")).toBe(true);
    expect(shouldSanctionActor("kick")).toBe(true);
    expect(shouldSanctionActor("ban_add")).toBe(true);
    expect(shouldSanctionActor("member_prune")).toBe(true);

    expect(shouldSanctionActor("channel_overwrite")).toBe(false);
    expect(shouldSanctionActor("permission_escalation")).toBe(false);
    expect(shouldSanctionActor("role_update")).toBe(false);
    expect(shouldSanctionActor("channel_update")).toBe(false);
    expect(shouldSanctionActor("guild_update")).toBe(false);
    expect(shouldSanctionActor("webhook")).toBe(false);
    expect(shouldSanctionActor("bot_add")).toBe(false);
  });
});

describe("high-confidence containment policy", () => {
  it("does not contain a one-off reversible admin change", () => {
    expect(auditContainmentDecision({
      action:"permission_escalation",
      count:1,
      thresholdValue:1,
      crossActionScore:12,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:false,lockdown:false});
  });

  it("contains repeated overwrite storms without sanctioning on the first few edits", () => {
    expect(auditContainmentDecision({
      action:"channel_overwrite",
      count:4,
      thresholdValue:4,
      crossActionScore:20,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:false,lockdown:false});

    expect(auditContainmentDecision({
      action:"channel_overwrite",
      count:12,
      thresholdValue:4,
      crossActionScore:60,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:true,lockdown:true});
  });

  it("records but does not enforce one-off ambiguous admin actions", () => {
    expect(auditContainmentDecision({
      action:"bot_add",
      count:1,
      thresholdValue:1,
      crossActionScore:12,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:true,
      selfPrivilegeGrant:false
    })).toEqual({contain:false,lockdown:false});

    expect(auditContainmentDecision({
      action:"permission_escalation",
      count:1,
      thresholdValue:1,
      crossActionScore:12,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:true
    })).toEqual({contain:false,lockdown:false});

    expect(auditContainmentDecision({
      action:"channel_overwrite",
      count:1,
      thresholdValue:4,
      crossActionScore:6,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:true,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:false,lockdown:false});
  });

  it("enforces only after repeated high-risk admin signals", () => {
    expect(auditContainmentDecision({
      action:"bot_add",
      count:2,
      thresholdValue:1,
      crossActionScore:24,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:true,
      selfPrivilegeGrant:false
    })).toEqual({contain:false,lockdown:false});

    expect(auditContainmentDecision({
      action:"permission_escalation",
      count:3,
      thresholdValue:1,
      crossActionScore:36,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:true
    })).toEqual({contain:true,lockdown:false});

    expect(auditContainmentDecision({
      action:"channel_overwrite",
      count:3,
      thresholdValue:4,
      crossActionScore:18,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:true,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:true,lockdown:true});
  });

  it("ordinary destructive cleanup stays below the automatic floor", () => {
    expect(auditContainmentDecision({
      action:"channel_delete",
      count:4,
      thresholdValue:2,
      crossActionScore:28,
      crossActionThreshold:12,
      destructiveKinds:1,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:false,lockdown:false});

    expect(auditContainmentDecision({
      action:"kick",
      count:5,
      thresholdValue:5,
      crossActionScore:20,
      crossActionThreshold:12,
      destructiveKinds:1,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:false,lockdown:false});
  });

  it("locks down confirmed destructive bursts", () => {
    expect(auditContainmentDecision({
      action:"channel_delete",
      count:5,
      thresholdValue:2,
      crossActionScore:35,
      crossActionThreshold:12,
      destructiveKinds:1,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:true,lockdown:true});

    expect(auditContainmentDecision({
      action:"kick",
      count:1,
      thresholdValue:5,
      crossActionScore:18,
      crossActionThreshold:12,
      destructiveKinds:2,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false
    })).toEqual({contain:true,lockdown:true});
  });
});

describe("bot coexistence containment policy", () => {
  it("does not lockdown a bot for a burst of reversible configuration changes", () => {
    expect(auditContainmentDecision({
      action:"channel_overwrite",
      count:50,
      thresholdValue:4,
      crossActionScore:100,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false,
      actorIsBot:true
    })).toEqual({contain:false,lockdown:false});
  });

  it("still locks down destructive bot activity", () => {
    expect(auditContainmentDecision({
      action:"channel_delete",
      count:5,
      thresholdValue:2,
      crossActionScore:35,
      crossActionThreshold:12,
      destructiveKinds:1,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:false,
      selfPrivilegeGrant:false,
      actorIsBot:true
    })).toEqual({contain:true,lockdown:true});
  });

  it("keeps privileged bot additions review-only even when repeated", () => {
    expect(auditContainmentDecision({
      action:"bot_add",
      count:20,
      thresholdValue:1,
      crossActionScore:100,
      crossActionThreshold:12,
      destructiveKinds:0,
      securitySelfOverwrite:false,
      pruneMembers:0,
      highRiskBotAdd:true,
      selfPrivilegeGrant:false,
      actorIsBot:false
    })).toEqual({contain:false,lockdown:false});
  });
});

describe("false-positive-resistant message policy", () => {
  it("does not punish normal fast conversation at the old threshold", () => {
    expect(isStrongSpam({
      messageCount:6,
      repeatedCount:1,
      mentions:0,
      spamMessages:6,
      mentionLimit:8
    })).toBe(false);
  });

  it("still catches repeated spam, extreme bursts, and mass mentions", () => {
    expect(isStrongSpam({
      messageCount:6,
      repeatedCount:3,
      mentions:0,
      spamMessages:6,
      mentionLimit:8
    })).toBe(true);
    expect(isStrongSpam({
      messageCount:12,
      repeatedCount:1,
      mentions:0,
      spamMessages:6,
      mentionLimit:8
    })).toBe(true);
    expect(isStrongSpam({
      messageCount:1,
      repeatedCount:1,
      mentions:16,
      spamMessages:6,
      mentionLimit:8
    })).toBe(true);
  });

  it("does not timeout a borderline mass mention", () => {
    expect(isStrongSpam({
      messageCount:1,
      repeatedCount:1,
      mentions:12,
      spamMessages:6,
      mentionLimit:8
    })).toBe(false);
  });

  it("does not punish a single message with the former mention threshold", () => {
    expect(isStrongSpam({
      messageCount:1,
      repeatedCount:1,
      mentions:8,
      spamMessages:6,
      mentionLimit:8
    })).toBe(false);
  });
});

describe("raid confidence policy", () => {
  it("treats a join burst alone as suspicious but not confirmed", () => {
    expect(raidConfidence({joins:8,youngJoins:0,raidJoins:8}))
      .toEqual({suspicious:true,confirmed:false});
  });

  it("confirms raids when the burst is dominated by new accounts or is extreme", () => {
    expect(raidConfidence({joins:8,youngJoins:5,raidJoins:8}))
      .toEqual({suspicious:true,confirmed:true});
    expect(raidConfidence({joins:16,youngJoins:0,raidJoins:8}))
      .toEqual({suspicious:true,confirmed:true});
  });
});


describe("Main Bot channel recovery overwrite", () => {
  it("preserves unrelated overwrites and restores only the dashboard access mask", () => {
    const repaired = buildManagedBotRecoveryOverwrites([
      { id: "guild", type: 0, allow: "64", deny: "2048" },
      { id: "main", type: 1, allow: "64", deny: String(1024n | 16n | 268435456n) }
    ], "main");

    expect(repaired.find(item => item.id === "guild")).toEqual({
      id: "guild",
      type: 0,
      allow: "64",
      deny: "2048"
    });

    const main = repaired.find(item => item.id === "main" && item.type === 1);
    expect(main).toBeTruthy();
    const allow = BigInt(main!.allow);
    const deny = BigInt(main!.deny);
    for (const bit of [16n,1024n,2048n,8192n,16384n,32768n,65536n,268435456n]) {
      expect((allow & bit) === bit).toBe(true);
      expect((deny & bit) === 0n).toBe(true);
    }
    expect((allow & 64n) === 64n).toBe(true);
  });
});
