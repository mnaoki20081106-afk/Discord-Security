import type {
  AuditEntry,
  DiscordMemberAddEvent,
  DiscordMessageEvent,
  Env,
  SecuritySettings
} from "./types";
import {
  advanceAuditCursor,
  claimAuditEntry,
  getAuditCursor,
  getSecuritySettings,
  hasMaintenanceLease,
  recordIncident
} from "./db";
import {
  botFetch,
  botJson,
  dangerousPermissionAdded,
  deleteMessage,
  deleteWebhook,
  enterLockdown,
  getGuildOwnerId,
  getMember,
  kickMember,
  rollbackRolePermissions,
  sendSecurityLog,
  stripDangerousRoles,
  timeoutMember
} from "./discord";

type ActionKey =
  | "channel_create"
  | "channel_update"
  | "channel_delete"
  | "role_create"
  | "role_update"
  | "role_delete"
  | "permission_escalation"
  | "ban_add"
  | "kick"
  | "webhook"
  | "bot_add"
  | "guild_update"
  | "automod_change"
  | "integration_change";

type ActionSpec = {
  key: ActionKey;
  threshold: keyof SecuritySettings["thresholds"];
  weight: number;
  module: keyof SecuritySettings["modules"];
  critical?: boolean;
};

type WeightedAction = { at: number; weight: number; key: ActionKey };

const ACTION_SPECS: Record<number, ActionSpec> = {
  1: { key: "guild_update", threshold: "guildUpdate", weight: 5, module: "guildGuard" },
  10: { key: "channel_create", threshold: "channelCreate", weight: 2, module: "antiNuke" },
  11: { key: "channel_update", threshold: "channelUpdate", weight: 2, module: "antiNuke" },
  12: { key: "channel_delete", threshold: "channelDelete", weight: 7, module: "antiNuke", critical: true },
  20: { key: "kick", threshold: "kick", weight: 4, module: "memberGuard" },
  22: { key: "ban_add", threshold: "banAdd", weight: 4, module: "memberGuard" },
  28: { key: "bot_add", threshold: "botAdd", weight: 12, module: "botGuard", critical: true },
  30: { key: "role_create", threshold: "roleCreate", weight: 2, module: "roleGuard" },
  31: { key: "role_update", threshold: "roleUpdate", weight: 4, module: "roleGuard" },
  32: { key: "role_delete", threshold: "roleDelete", weight: 8, module: "roleGuard", critical: true },
  50: { key: "webhook", threshold: "webhook", weight: 7, module: "webhookGuard" },
  51: { key: "webhook", threshold: "webhook", weight: 7, module: "webhookGuard" },
  52: { key: "webhook", threshold: "webhook", weight: 7, module: "webhookGuard" },
  80: { key: "integration_change", threshold: "guildUpdate", weight: 5, module: "guildGuard" },
  81: { key: "integration_change", threshold: "guildUpdate", weight: 5, module: "guildGuard" },
  82: { key: "integration_change", threshold: "guildUpdate", weight: 5, module: "guildGuard" },
  140: { key: "automod_change", threshold: "automodChange", weight: 9, module: "automodGuard", critical: true },
  141: { key: "automod_change", threshold: "automodChange", weight: 9, module: "automodGuard", critical: true },
  142: { key: "automod_change", threshold: "automodChange", weight: 11, module: "automodGuard", critical: true }
};

const SUSPICIOUS_TERMS = [
  "nitro", "gift", "claim", "airdrop", "wallet", "login", "verify",
  "steam", "discord", "support", "giveaway", "bonus", "reward"
];
const DANGEROUS_EXTENSIONS = new Set([
  "exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
  "wsf", "wsh", "msi", "msp", "jar", "lnk", "reg", "hta"
]);
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"
]);

function snowflakeCreatedAt(id: string): number {
  try {
    return Number((BigInt(id) >> 22n) + 1420070400000n);
  } catch {
    return 0;
  }
}

function domainMatches(host: string, rule: string): boolean {
  const normalized = rule.toLowerCase().replace(/^\.+|\.+$/g, "");
  return host === normalized || host.endsWith("." + normalized);
}

function extractUrls(content: string): URL[] {
  const found = content.match(/https?:\/\/[^\s<>{}\[\]"']+/gi) ?? [];
  const urls: URL[] = [];
  for (const raw of found.slice(0, 20)) {
    try {
      urls.push(new URL(raw.replace(/[),.!?]+$/, "")));
    } catch {
      // malformed URLs are ignored rather than punished
    }
  }
  return urls;
}

export function scoreUrl(url: URL, settings: SecuritySettings): number {
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (settings.allowedDomains.some(domain => domainMatches(host, domain))) return 0;
  if (settings.blockedDomains.some(domain => domainMatches(host, domain))) return 100;

  let score = 0;
  if (host.startsWith("xn--") || host.includes(".xn--")) score += 45;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":")) score += 35;
  if (url.username || url.password) score += 35;
  if (host.split(".").length >= 5) score += 15;
  if (SHORTENERS.has(host)) score += 15;

  const haystack = (host + url.pathname).toLowerCase();
  const suspicious = SUSPICIOUS_TERMS.filter(term => haystack.includes(term));
  if (suspicious.length >= 2) score += 45;
  else if (suspicious.length === 1) score += 25;

  if (/%40|%2f|%5c|@/i.test(url.href)) score += 15;
  return score;
}

function dangerousAttachment(filename: string | undefined): boolean {
  const ext = String(filename ?? "").toLowerCase().split(".").pop() ?? "";
  return DANGEROUS_EXTENSIONS.has(ext);
}

export class SecurityEngine {
  private actionWindows = new Map<string, number[]>();
  private weightedActions = new Map<string, WeightedAction[]>();
  private messageWindows = new Map<string, number[]>();
  private linkWindows = new Map<string, number[]>();
  private joinWindows = new Map<string, number[]>();
  private raidModeUntil = new Map<string, number>();
  private sanctionCooldown = new Map<string, number>();
  private settingsCache = new Map<string, { value: SecuritySettings; until: number }>();
  private ownerCache = new Map<string, { ownerId: string | null; until: number }>();

  constructor(private readonly env: Env) {}

  private async settings(guildId: string): Promise<SecuritySettings> {
    const cached = this.settingsCache.get(guildId);
    if (cached && cached.until > Date.now()) return cached.value;
    const value = await getSecuritySettings(this.env, guildId);
    this.settingsCache.set(guildId, { value, until: Date.now() + 10_000 });
    return value;
  }

  invalidateSettings(guildId: string): void {
    this.settingsCache.delete(guildId);
  }

  private windowCount(key: string, seconds: number): number {
    const now = Date.now();
    const history = (this.actionWindows.get(key) ?? [])
      .filter(at => now - at <= seconds * 1000);
    history.push(now);
    this.actionWindows.set(key, history);
    return history.length;
  }

  private weightedScore(
    guildId: string,
    actorId: string,
    spec: ActionSpec,
    seconds: number
  ): number {
    const key = guildId + ":" + actorId;
    const now = Date.now();
    const history = (this.weightedActions.get(key) ?? [])
      .filter(item => now - item.at <= seconds * 1000);
    history.push({ at: now, weight: spec.weight, key: spec.key });
    this.weightedActions.set(key, history);
    return history.reduce((total, item) => total + item.weight, 0);
  }

  private async trusted(
    guildId: string,
    actorId: string,
    settings: SecuritySettings
  ): Promise<boolean> {
    if (actorId === this.env.DISCORD_APPLICATION_ID) return true;
    if (settings.trustedUserIds.includes(actorId)) return true;

    let owner = this.ownerCache.get(guildId);
    if (!owner || owner.until <= Date.now()) {
      owner = {
        ownerId: await getGuildOwnerId(this.env, guildId),
        until: Date.now() + 60_000
      };
      this.ownerCache.set(guildId, owner);
    }
    // The guild owner is deliberately not fully trusted here. If the owner's
    // account is compromised, destructive actions must still be able to
    // trigger incident logging and server lockdown. Personal sanctions are
    // skipped separately because Discord does not allow a bot to moderate
    // the guild owner.
    if (settings.trustedRoleIds.length) {
      const member = await getMember(this.env, guildId, actorId);
      if (member?.roles?.some(role => settings.trustedRoleIds.includes(role))) {
        return true;
      }
    }
    return false;
  }

  private async sanction(
    guildId: string,
    actorId: string,
    settings: SecuritySettings,
    reason: string
  ): Promise<void> {
    const key = guildId + ":" + actorId;
    if ((this.sanctionCooldown.get(key) ?? 0) > Date.now()) return;
    this.sanctionCooldown.set(key, Date.now() + 30_000);

    if (settings.mode === "audit") return;

    const ownerId = await getGuildOwnerId(this.env, guildId);
    if (ownerId === actorId) return;

    const member = await getMember(this.env, guildId, actorId);
    if (member?.user?.bot) {
      if (settings.response.kickMaliciousBots) {
        await kickMember(
          this.env,
          guildId,
          actorId,
          "Discord Security: " + reason
        ).catch(() => false);
      }
      return;
    }

    if (settings.response.stripDangerousRoles) {
      await stripDangerousRoles(this.env, guildId, actorId).catch(() => 0);
    }
    await timeoutMember(
      this.env,
      guildId,
      actorId,
      settings.response.timeoutMinutes
    ).catch(() => false);
  }

  private async trigger(
    guildId: string,
    actorId: string,
    settings: SecuritySettings,
    spec: ActionSpec,
    detail: Record<string, unknown>
  ): Promise<void> {
    const summary = `${spec.key} の異常操作を検知し、実行者を隔離しました`;
    await recordIncident(this.env, {
      guildId,
      actorId,
      kind: spec.key,
      severity: spec.critical ? "critical" : "high",
      summary,
      data: detail
    });

    await sendSecurityLog(
      this.env,
      guildId,
      settings,
      "Security Incident",
      `<@${actorId}> の **${spec.key}** を検知しました。\n` +
      "危険権限の剥奪・隔離・Lockdownを安全設定に従って実行します。",
      true
    );

    await this.sanction(guildId, actorId, settings, spec.key);

    if (settings.response.autoLockdown && settings.mode === "enforce") {
      await enterLockdown(
        this.env,
        guildId,
        settings.response.lockdownMinutes,
        spec.key + " by " + actorId
      ).catch(() => false);
    }
  }

  private rolePermissionChange(entry: AuditEntry): {
    escalation: boolean;
    oldPermissions: string | null;
  } {
    if (entry.action_type !== 31) return { escalation: false, oldPermissions: null };
    const change = entry.changes?.find(item => item.key === "permissions");
    if (!change) return { escalation: false, oldPermissions: null };
    return {
      escalation: dangerousPermissionAdded(change.old_value, change.new_value),
      oldPermissions: change.old_value == null ? null : String(change.old_value)
    };
  }

  private async dangerousMemberRoleAdds(entry: AuditEntry): Promise<string[]> {
    if (entry.action_type !== 25 || !entry.target_id) return [];
    const added = entry.changes?.find(item => item.key === "$add")?.new_value;
    if (!Array.isArray(added)) return [];
    const roleIds = added
      .map(item => String((item as { id?: unknown })?.id ?? ""))
      .filter(Boolean);
    if (!roleIds.length) return [];
    const roles = await botJson<Array<{ id: string; permissions: string }>>(
      this.env,
      `/guilds/${entry.guild_id}/roles`
    ).catch(() => []);
    return roles
      .filter(role => roleIds.includes(role.id))
      .filter(role => {
        try {
          const bits = BigInt(role.permissions);
          const dangerous =
            (1n << 1n) | (1n << 2n) | (1n << 3n) | (1n << 4n) |
            (1n << 5n) | (1n << 28n) | (1n << 29n) | (1n << 40n);
          return (bits & dangerous) !== 0n;
        } catch {
          return false;
        }
      })
      .map(role => role.id);
  }

  async handleAudit(entry: AuditEntry): Promise<void> {
    const guildId = entry.guild_id;
    if (!guildId || !entry.id) return;
    if (!(await claimAuditEntry(this.env, guildId, entry.id))) return;
    await advanceAuditCursor(this.env, guildId, entry.id);

    const actorId = entry.user_id ?? "";
    if (!actorId) return;

    const settings = await this.settings(guildId);
    if (!settings.enabled) return;
    if (await this.trusted(guildId, actorId, settings)) return;

    const permissionChange = this.rolePermissionChange(entry);
    const dangerousMemberRoles = await this.dangerousMemberRoleAdds(entry);
    let spec = ACTION_SPECS[entry.action_type];

    if (permissionChange.escalation || dangerousMemberRoles.length) {
      spec = {
        key: "permission_escalation",
        threshold: "automodChange",
        weight: 12,
        module: "permissionGuard",
        critical: true
      };
    }

    if (!spec || !settings.modules[spec.module]) return;
    if (await hasMaintenanceLease(this.env, guildId, actorId, spec.key)) return;

    if (
      spec.key === "bot_add" &&
      entry.target_id &&
      settings.allowedBotIds.includes(entry.target_id)
    ) {
      return;
    }

    if (permissionChange.escalation && entry.target_id && permissionChange.oldPermissions) {
      if (settings.mode === "enforce") {
        await rollbackRolePermissions(
          this.env,
          guildId,
          entry.target_id,
          permissionChange.oldPermissions
        ).catch(() => false);
      }
    }

    if (dangerousMemberRoles.length && entry.target_id && settings.mode === "enforce") {
      for (const roleId of dangerousMemberRoles) {
        await botFetch(
          this.env,
          `/guilds/${guildId}/members/${entry.target_id}/roles/${roleId}`,
          {
            method: "DELETE",
            headers: {
              "X-Audit-Log-Reason": "Discord Security: unauthorized dangerous role assignment"
            }
          }
        ).catch(() => undefined);
      }
    }

    if (spec.key === "bot_add" && entry.target_id && settings.mode === "enforce") {
      await kickMember(
        this.env,
        guildId,
        entry.target_id,
        "Discord Security: unauthorized bot addition"
      ).catch(() => false);
    }

    if (
      spec.key === "webhook" &&
      entry.action_type === 50 &&
      entry.target_id &&
      settings.mode === "enforce"
    ) {
      await deleteWebhook(this.env, entry.target_id).catch(() => false);
    }

    const thresholdValue = Number(settings.thresholds[spec.threshold]);
    const count = this.windowCount(
      guildId + ":" + actorId + ":" + spec.key,
      settings.thresholds.actionWindowSeconds
    );
    const score = this.weightedScore(
      guildId,
      actorId,
      spec,
      settings.thresholds.crossActionWindowSeconds
    );

    const immediate = spec.key === "permission_escalation" || spec.key === "bot_add";
    if (
      immediate ||
      count >= thresholdValue ||
      score >= settings.thresholds.crossActionScore
    ) {
      await this.trigger(guildId, actorId, settings, spec, {
        auditEntryId: entry.id,
        actionType: entry.action_type,
        targetId: entry.target_id ?? null,
        actionCount: count,
        crossActionScore: score
      });
    }
  }

  async handleJoin(event: DiscordMemberAddEvent): Promise<void> {
    if (event.user.bot) return;
    const settings = await this.settings(event.guild_id);
    if (!settings.enabled || !settings.modules.antiRaid) return;

    const now = Date.now();
    const windowMs = settings.thresholds.raidWindowSeconds * 1000;
    const history = (this.joinWindows.get(event.guild_id) ?? [])
      .filter(at => now - at <= windowMs);
    history.push(now);
    this.joinWindows.set(event.guild_id, history);

    if (history.length >= settings.thresholds.raidJoins) {
      this.raidModeUntil.set(
        event.guild_id,
        now + settings.response.lockdownMinutes * 60_000
      );
      await recordIncident(this.env, {
        guildId: event.guild_id,
        actorId: null,
        kind: "raid",
        severity: "critical",
        summary: `${settings.thresholds.raidWindowSeconds}秒で${history.length}人の参加を検知`,
        data: { joins: history.length }
      });
      await sendSecurityLog(
        this.env,
        event.guild_id,
        settings,
        "Raid detected",
        `${settings.thresholds.raidWindowSeconds}秒以内に${history.length}人が参加しました。`,
        true
      );
      if (settings.mode === "enforce" && settings.response.autoLockdown) {
        await enterLockdown(
          this.env,
          event.guild_id,
          settings.response.lockdownMinutes,
          "join raid"
        ).catch(() => false);
      }
    }

    const accountAge = now - snowflakeCreatedAt(event.user.id);
    const tooYoung =
      accountAge >= 0 &&
      accountAge < settings.thresholds.minAccountAgeHours * 60 * 60_000;
    const raidActive = (this.raidModeUntil.get(event.guild_id) ?? 0) > now;
    if (
      settings.mode === "enforce" &&
      settings.response.quarantineRaidJoins &&
      (raidActive || (tooYoung && history.length >= Math.max(3, Math.floor(settings.thresholds.raidJoins / 2))))
    ) {
      await timeoutMember(
        this.env,
        event.guild_id,
        event.user.id,
        settings.response.timeoutMinutes
      ).catch(() => false);
    }
  }

  private messageWindow(
    map: Map<string, number[]>,
    key: string,
    seconds: number
  ): number {
    const now = Date.now();
    const history = (map.get(key) ?? []).filter(at => now - at <= seconds * 1000);
    history.push(now);
    map.set(key, history);
    return history.length;
  }

  async handleMessage(event: DiscordMessageEvent): Promise<void> {
    if (!event.guild_id || event.author.bot) return;
    const guildId = event.guild_id;
    const settings = await this.settings(guildId);
    if (!settings.enabled) return;

    const roles = event.member?.roles ?? [];
    if (
      settings.trustedUserIds.includes(event.author.id) ||
      roles.some(role => settings.trustedRoleIds.includes(role))
    ) return;

    const userKey = guildId + ":" + event.author.id;
    let violation: string | null = null;
    let metadata: Record<string, unknown> = {};

    if (settings.modules.antiSpam) {
      const count = this.messageWindow(
        this.messageWindows,
        userKey,
        settings.thresholds.spamWindowSeconds
      );
      const mentions =
        (event.mentions?.length ?? 0) + (event.mention_roles?.length ?? 0);
      if (
        count >= settings.thresholds.spamMessages ||
        mentions >= settings.thresholds.mentionLimit
      ) {
        violation = "spam";
        metadata = { messageCount: count, mentions };
      }
    }

    const urls = extractUrls(event.content ?? "");
    if (!violation && settings.modules.antiPhishing && urls.length) {
      const risky = urls
        .map(url => ({ domain: url.hostname.toLowerCase(), score: scoreUrl(url, settings) }))
        .filter(item => item.score >= 50);
      const linkCount = this.messageWindow(
        this.linkWindows,
        userKey,
        settings.thresholds.linkWindowSeconds
      );
      if (risky.length || (urls.length > 0 && linkCount >= settings.thresholds.linkBurst)) {
        violation = risky.length ? "phishing_url" : "link_burst";
        metadata = {
          domains: [...new Set(urls.map(url => url.hostname.toLowerCase()))].slice(0, 10),
          maxRisk: risky.reduce((max, item) => Math.max(max, item.score), 0)
        };
      }
    }

    if (!violation && settings.modules.dangerousAttachments) {
      const dangerous = (event.attachments ?? [])
        .filter(item => dangerousAttachment(item.filename))
        .map(item => String(item.filename ?? "unknown"));
      if (dangerous.length) {
        violation = "dangerous_attachment";
        metadata = { filenames: dangerous.slice(0, 10) };
      }
    }

    if (!violation) return;

    await recordIncident(this.env, {
      guildId,
      actorId: event.author.id,
      kind: violation,
      severity: violation === "spam" ? "medium" : "high",
      summary: `危険な投稿を遮断しました: ${violation}`,
      data: metadata
    });

    if (settings.mode === "enforce") {
      if (settings.response.deleteUnsafeMessages) {
        await deleteMessage(this.env, event.channel_id, event.id).catch(() => false);
      }
      await timeoutMember(
        this.env,
        guildId,
        event.author.id,
        violation === "spam" ? 5 : settings.response.timeoutMinutes
      ).catch(() => false);
    }

    await sendSecurityLog(
      this.env,
      guildId,
      settings,
      "Message Security",
      `<@${event.author.id}> の投稿を **${violation}** として遮断しました。\n` +
      "本文や添付ファイル本体はSecurity Logへ保存していません。",
      violation !== "spam"
    );
  }

  async reconcileGuild(guildId: string): Promise<void> {
    const payload = await botJson<{ audit_log_entries?: AuditEntry[] }>(
      this.env,
      `/guilds/${guildId}/audit-logs?limit=50`
    ).catch(() => null);
    const entries = payload?.audit_log_entries ?? [];
    if (!entries.length) return;

    const newest = entries[0]!.id;
    const cursor = await getAuditCursor(this.env, guildId);

    // First sight of a guild establishes a baseline instead of punishing
    // historical legitimate admin actions performed before Security connected.
    if (!cursor) {
      await advanceAuditCursor(this.env, guildId, newest);
      return;
    }

    const fresh: AuditEntry[] = [];
    for (const raw of entries) {
      if (raw.id === cursor) break;
      fresh.push({ ...raw, guild_id: raw.guild_id || guildId });
    }

    fresh.reverse();
    for (const entry of fresh) {
      await this.handleAudit(entry);
    }
    await advanceAuditCursor(this.env, guildId, newest);
  }

}
