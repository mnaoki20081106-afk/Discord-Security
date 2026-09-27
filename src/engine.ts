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
  isManagedServiceBot,
  recordIncident
} from "./db";
import {
  botFetch,
  botJson,
  dangerousPermissionAdded,
  deleteMessage,
  enforceGuildSafetyBaseline,
  deleteWebhook,
  enterLockdown,
  getGuildOwnerId,
  getMember,
  humanMemberOutranksSecurityById,
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
  | "channel_overwrite"
  | "role_create"
  | "role_update"
  | "role_delete"
  | "permission_escalation"
  | "ban_add"
  | "member_prune"
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

export function shouldSanctionActor(action: ActionKey): boolean {
  return new Set<ActionKey>([
    "channel_delete",
    "role_delete",
    "kick",
    "ban_add",
    "member_prune"
  ]).has(action);
}

export function shouldAutoSanctionActor(input:{
  action:ActionKey;
  count:number;
  thresholdValue:number;
  crossActionScore:number;
  crossActionThreshold:number;
  destructiveKinds:number;
  actorIsBot?:boolean;
}):boolean{
  if(!shouldSanctionActor(input.action)) return false;
  const floor=
    input.action==="channel_delete" ? 10 :
    input.action==="role_delete" ? 8 :
    input.action==="kick" ? 15 :
    input.action==="ban_add" ? 12 :
    Number.POSITIVE_INFINITY;
  const extremeSingleClass=
    input.count>=Math.max(input.thresholdValue*2,floor);
  const extremeMixed=
    input.destructiveKinds>=3 &&
    input.crossActionScore>=Math.max(
      input.crossActionThreshold*2,
      30
    );

  if(input.actorIsBot){
    // Other moderation/security bots can legitimately perform many kicks or
    // bans during a raid. Never kick another bot solely for moderation volume.
    // Structural destruction is qualitatively different: repeated channel or
    // role deletion remains strong evidence that the bot itself is hostile or
    // compromised, so automatic bot removal stays enabled for that case.
    const structuralAction=
      input.action==="channel_delete" ||
      input.action==="role_delete";
    return structuralAction && (extremeSingleClass||extremeMixed);
  }

  return extremeSingleClass||extremeMixed;
}

const DESTRUCTIVE_ACTIONS = new Set<ActionKey>([
  "channel_delete",
  "role_delete",
  "kick",
  "ban_add",
  "member_prune"
]);

export function isDestructiveAuditAction(action: ActionKey): boolean {
  return DESTRUCTIVE_ACTIONS.has(action);
}

export function auditContainmentDecision(input: {
  action: ActionKey;
  count: number;
  thresholdValue: number;
  crossActionScore: number;
  crossActionThreshold: number;
  destructiveKinds: number;
  securitySelfOverwrite: boolean;
  pruneMembers: number;
  highRiskBotAdd: boolean;
  selfPrivilegeGrant: boolean;
  actorIsBot?: boolean;
}): { contain: boolean; lockdown: boolean } {
  const threshold=Math.max(1,input.thresholdValue);
  const destructiveMinimum=
    input.action==="channel_delete" ? 5 :
    input.action==="role_delete" ? 4 :
    input.action==="kick" ? 8 :
    input.action==="ban_add" ? 6 :
    threshold;
  const destructiveBurst=
    isDestructiveAuditAction(input.action) &&
    input.count>=Math.max(threshold,destructiveMinimum);
  const mixedDestructiveBurst=
    input.destructiveKinds>=2 &&
    input.crossActionScore>=Math.max(
      input.crossActionThreshold+6,
      Math.ceil(input.crossActionThreshold*1.5)
    );
  // Configuration-heavy bots routinely create/update roles, channels,
  // overwrites, webhooks and integrations in short bursts. Those operations
  // are reversible and must not globally lock a guild merely because the
  // actor is a bot. Destructive actions are still evaluated below.
  const nonDestructiveBurst=
    !input.actorIsBot &&
    input.action!=="bot_add" &&
    !isDestructiveAuditAction(input.action) &&
    input.count>=Math.max(6,threshold*3);
  const pruneBurst=
    input.action==="member_prune" &&
    input.pruneMembers>=threshold;

  const repeatedSecurityTamper=
    input.securitySelfOverwrite && input.count>=3;
  // A newly-added bot having moderation/admin permissions is not proof that
  // the bot is malicious. Keep bot-add risk as review-only evidence and judge
  // the bot by what it subsequently does.
  const repeatedSelfPrivilegeGrant=
    input.selfPrivilegeGrant && input.count>=3;

  const contain=
    repeatedSecurityTamper ||
    repeatedSelfPrivilegeGrant ||
    pruneBurst ||
    destructiveBurst ||
    mixedDestructiveBurst ||
    nonDestructiveBurst;

  // Ambiguous single events never cause a global lockdown. Lockdown requires
  // repeated Security tampering or confirmed destructive/repetitive activity.
  const lockdown=
    repeatedSecurityTamper ||
    pruneBurst ||
    destructiveBurst ||
    mixedDestructiveBurst ||
    nonDestructiveBurst;

  return {contain,lockdown};
}

export function isStrongSpam(input:{
  messageCount:number;
  repeatedCount:number;
  mentions:number;
  spamMessages:number;
  mentionLimit:number;
}):boolean{
  const burstFloor=Math.max(input.spamMessages*2,input.spamMessages+4);
  const repeated=
    input.messageCount>=input.spamMessages &&
    input.repeatedCount>=3;
  const massMention=input.mentions>=Math.max(input.mentionLimit*2,15);
  return input.messageCount>=burstFloor||repeated||massMention;
}

export function raidConfidence(input:{
  joins:number;
  youngJoins:number;
  raidJoins:number;
}):{suspicious:boolean;confirmed:boolean}{
  const threshold=Math.max(2,input.raidJoins);
  const suspicious=input.joins>=threshold;
  const confirmed=
    input.joins>=threshold*2 ||
    (
      suspicious &&
      input.youngJoins>=Math.max(3,Math.ceil(threshold*0.6))
    );
  return {suspicious,confirmed};
}

type WeightedAction = { at: number; weight: number; key: ActionKey };
type SevereContentEvent = { at: number; userId: string };

const ACTION_SPECS: Record<number, ActionSpec> = {
  1: { key: "guild_update", threshold: "guildUpdate", weight: 5, module: "guildGuard" },
  10: { key: "channel_create", threshold: "channelCreate", weight: 2, module: "antiNuke" },
  11: { key: "channel_update", threshold: "channelUpdate", weight: 2, module: "antiNuke" },
  12: { key: "channel_delete", threshold: "channelDelete", weight: 7, module: "antiNuke", critical: true },
  13: { key: "channel_overwrite", threshold: "channelOverwrite", weight: 4, module: "permissionGuard" },
  14: { key: "channel_overwrite", threshold: "channelOverwrite", weight: 5, module: "permissionGuard" },
  15: { key: "channel_overwrite", threshold: "channelOverwrite", weight: 6, module: "permissionGuard", critical: true },
  20: { key: "kick", threshold: "kick", weight: 4, module: "memberGuard" },
  21: { key: "member_prune", threshold: "memberPrune", weight: 12, module: "memberGuard", critical: true },
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

export function isSecurityBotSelfTarget(
  env: Pick<Env, "DISCORD_APPLICATION_ID">,
  targetId: string
): boolean {
  const applicationId = env.DISCORD_APPLICATION_ID?.trim();
  return Boolean(applicationId && targetId === applicationId);
}

export function auditEntryCreatedAt(entryId: string): number | null {
  try {
    const snowflake = BigInt(entryId);
    return Number((snowflake >> 22n) + 1420070400000n);
  } catch {
    return null;
  }
}

export function classifyAuditAction(actionType: number): string | null {
  return ACTION_SPECS[actionType]?.key ?? null;
}

const SUSPICIOUS_TERMS = [
  "nitro", "gift", "claim", "airdrop", "wallet", "login", "verify",
  "steam", "discord", "support", "giveaway", "bonus", "reward"
];
const HIGH_RISK_EXECUTABLE_EXTENSIONS = new Set([
  "exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe",
  "wsf", "wsh", "msi", "msp", "lnk", "reg", "hta"
]);
const REVIEW_ONLY_ATTACHMENT_EXTENSIONS = new Set(["js","jse","jar"]);
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
  // Explicit deny rules always override allow rules. This prevents a stale
  // allowlist entry from neutralizing an emergency block pushed by admins.
  if (settings.blockedDomains.some(domain => domainMatches(host, domain))) return 100;
  if (settings.allowedDomains.some(domain => domainMatches(host, domain))) return 0;

  let score = 0;
  // A host such as discord.com.evil.example is not a Discord subdomain.
  // If a trusted domain string is embedded in an unrelated hostname, treat it
  // as a strong brand-lookalike signal instead of letting it sit just below
  // the enforcement threshold.
  if (settings.allowedDomains.some(domain => {
    const normalized = domain.toLowerCase().replace(/^\.+|\.+$/g, "");
    return normalized.length >= 4 &&
      host.includes(normalized) &&
      !domainMatches(host, normalized);
  })) score += 60;
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

function attachmentRisk(
  filename: string | undefined
): "high" | "review" | null {
  const ext = String(filename ?? "").toLowerCase().split(".").pop() ?? "";
  if (HIGH_RISK_EXECUTABLE_EXTENSIONS.has(ext)) return "high";
  if (REVIEW_ONLY_ATTACHMENT_EXTENSIONS.has(ext)) return "review";
  return null;
}

function deceptiveExecutableFilename(filename:string):boolean{
  return /\.(?:pdf|docx?|xlsx?|pptx?|txt|png|jpe?g|gif|webp|zip|rar)\.(?:exe|scr|com|bat|cmd|ps1|vbs|vbe|wsf|wsh|msi|msp|lnk|reg|hta)$/i
    .test(filename);
}

function normalizedMessageFingerprint(content: string): string {
  return content
    .toLowerCase()
    .replace(/https?:\/\/[^\s<>{}\[\]"']+/gi,"<url>")
    .replace(/\s+/g," ")
    .trim()
    .slice(0,500);
}

export type AuditBacklog = {
  entries: AuditEntry[];
  newestId: string | null;
  cursorFound: boolean;
  truncated: boolean;
  fetchFailed: boolean;
  pages: number;
};

export async function fetchAuditBacklog(
  env: Env,
  guildId: string,
  cursor: string | null,
  maxPages = 10
): Promise<AuditBacklog> {
  const fresh: AuditEntry[] = [];
  let newestId: string | null = null;
  let before: string | null = null;
  let cursorFound = false;
  let exhausted = false;
  let fetchFailed = false;
  let pages = 0;

  for (let page = 0; page < Math.max(1, maxPages); page++) {
    const query = new URLSearchParams({ limit: "100" });
    if (before) query.set("before", before);
    let payload: { audit_log_entries?: AuditEntry[] } | null = null;
    try {
      payload = await botJson<{ audit_log_entries?: AuditEntry[] }>(
        env,
        `/guilds/${guildId}/audit-logs?${query.toString()}`
      );
    } catch {
      fetchFailed = true;
      break;
    }

    const entries = payload.audit_log_entries ?? [];
    pages += 1;
    if (!entries.length) {
      exhausted = true;
      break;
    }
    if (!newestId) newestId = entries[0]!.id;

    // First sight establishes a baseline only. Historical actions from before
    // Security was installed must not be punished.
    if (!cursor) {
      return {
        entries: [],
        newestId,
        cursorFound: false,
        truncated: false,
        fetchFailed: false,
        pages
      };
    }

    for (const raw of entries) {
      if (raw.id === cursor) {
        cursorFound = true;
        break;
      }
      fresh.push({ ...raw, guild_id: raw.guild_id || guildId });
    }
    if (cursorFound) break;

    if (entries.length < 100) {
      exhausted = true;
      break;
    }
    before = entries[entries.length - 1]!.id;
  }

  return {
    entries: fresh,
    newestId,
    cursorFound,
    truncated: Boolean(
      cursor &&
      !cursorFound &&
      !exhausted &&
      !fetchFailed &&
      pages >= Math.max(1, maxPages)
    ),
    fetchFailed,
    pages
  };
}

export class SecurityEngine {
  private actionWindows = new Map<string, number[]>();
  private weightedActions = new Map<string, WeightedAction[]>();
  private messageWindows = new Map<string, number[]>();
  private linkWindows = new Map<string, number[]>();
  private attachmentWindows = new Map<string, number[]>();
  private repeatedMessageWindows = new Map<string, Array<{at:number;fingerprint:string}>>();
  private joinWindows = new Map<string, number[]>();
  private youngJoinWindows = new Map<string, number[]>();
  private severeContentWindows = new Map<string, SevereContentEvent[]>();
  private raidModeUntil = new Map<string, number>();
  private raidSuspicionLogUntil = new Map<string, number>();
  private raidLockdownUntil = new Map<string, number>();
  private contentOutbreakCooldown = new Map<string, number>();
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

  private weightedProfile(
    guildId: string,
    actorId: string,
    spec: ActionSpec,
    seconds: number
  ): { score:number; destructiveKinds:number } {
    const key = guildId + ":" + actorId;
    const now = Date.now();
    const history = (this.weightedActions.get(key) ?? [])
      .filter(item => now - item.at <= seconds * 1000);
    history.push({ at: now, weight: spec.weight, key: spec.key });
    this.weightedActions.set(key, history);
    return {
      score:history.reduce((total,item)=>total+item.weight,0),
      destructiveKinds:new Set(
        history
          .filter(item=>isDestructiveAuditAction(item.key))
          .map(item=>item.key)
      ).size
    };
  }

  private repeatedMessageCount(
    key:string,
    seconds:number,
    content:string
  ):number{
    const now=Date.now();
    const fingerprint=normalizedMessageFingerprint(content);
    const history=(this.repeatedMessageWindows.get(key)??[])
      .filter(item=>now-item.at<=seconds*1000);
    if(fingerprint) history.push({at:now,fingerprint});
    this.repeatedMessageWindows.set(key,history);
    if(!fingerprint) return 0;
    return history.filter(item=>item.fingerprint===fingerprint).length;
  }

  private async botHasDangerousPermissions(
    guildId:string,
    botId:string
  ):Promise<boolean>{
    try{
      const [member,roles]=await Promise.all([
        getMember(this.env,guildId,botId),
        botJson<Array<{id:string;permissions:string}>>(
          this.env,
          `/guilds/${guildId}/roles`
        )
      ]);
      if(!member) return false;
      const roleIds=new Set(member.roles??[]);
      let permissions=0n;
      for(const role of roles){
        if(role.id===guildId||roleIds.has(role.id)){
          permissions|=BigInt(role.permissions||"0");
        }
      }
      const dangerous=
        (1n<<1n)|(1n<<2n)|(1n<<3n)|(1n<<4n)|
        (1n<<5n)|(1n<<28n)|(1n<<29n)|(1n<<40n);
      return (permissions&dangerous)!==0n;
    }catch{
      // Failed inspection is not proof of malicious intent.
      return false;
    }
  }

  private async actorBotState(
    guildId: string,
    actorId: string,
    settings: SecuritySettings
  ): Promise<{ isBot: boolean; protectedBot: boolean }> {
    // Protect known infrastructure by identity before any Discord REST lookup.
    // A transient member-fetch failure must never make Main Bot kick-eligible.
    const protectedBot =
      actorId === this.env.MAIN_BOT_APPLICATION_ID?.trim() ||
      settings.allowedBotIds.includes(actorId) ||
      await isManagedServiceBot(this.env, guildId, actorId);
    if (protectedBot) return { isBot: true, protectedBot: true };

    const member = await getMember(this.env, guildId, actorId);
    if (!member) {
      // Unknown identity is not enough evidence for reversible-operation
      // containment. Treat it as automation for that gate; destructive actions
      // are still evaluated normally.
      return { isBot: true, protectedBot: false };
    }
    return { isBot: Boolean(member.user?.bot), protectedBot: false };
  }

  private async humanOperatorProtection(
    guildId: string,
    actorId: string
  ): Promise<"protected" | "unprotected" | "unknown"> {
    let owner = this.ownerCache.get(guildId);
    if (!owner || owner.until <= Date.now()) {
      owner = {
        ownerId: await getGuildOwnerId(this.env, guildId),
        until: Date.now() + 60_000
      };
      this.ownerCache.set(guildId, owner);
    }
    if (owner.ownerId === actorId) return "protected";

    const outranksSecurity = await humanMemberOutranksSecurityById(
      this.env,
      guildId,
      actorId
    );
    if (outranksSecurity === null) return "unknown";
    return outranksSecurity ? "protected" : "unprotected";
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

    const protectedBot =
      actorId === this.env.MAIN_BOT_APPLICATION_ID?.trim() ||
      settings.allowedBotIds.includes(actorId) ||
      await isManagedServiceBot(this.env, guildId, actorId);
    // Main/managed/explicitly-allowed service bots are infrastructure.
    // Never kick them automatically. If one is compromised, destructive
    // activity is contained with guild Lockdown instead.
    if (protectedBot) return;

    const member = await getMember(this.env, guildId, actorId);
    // Missing identity/hierarchy data is not sufficient evidence for a
    // personal sanction. Server-wide containment can still happen separately.
    if (!member) return;
    if (member.user?.bot) {
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

    const humanProtection = await this.humanOperatorProtection(guildId, actorId);
    if (humanProtection !== "unprotected") return;

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
    detail: Record<string, unknown>,
    sanctionActor = true,
    lockdown = true,
    protectedHumanOperator = false,
    actorHierarchyUnknown = false
  ): Promise<void> {
    const enforcing = settings.mode === "enforce";
    const summary = protectedHumanOperator
      ? lockdown && enforcing
        ? `${spec.key} を上位人間管理者から検知し、本人への自動制裁なしでLockdownしました`
        : `${spec.key} を上位人間管理者から検知しました（本人への自動制裁なし）`
      : actorHierarchyUnknown
        ? `${spec.key} を検知しました（実行者の階層確認に失敗したため個人制裁を保留）`
        : enforcing
          ? sanctionActor
            ? `${spec.key} の高信頼度な異常操作を検知し、実行者を隔離しました`
            : `${spec.key} の高信頼度な異常操作を検知し、対象を封じ込めました`
          : `${spec.key} の異常操作を検知しました（Audit only・自動処置なし）`;
    await recordIncident(this.env, {
      guildId,
      actorId,
      kind: spec.key,
      severity: spec.critical ? "critical" : "high",
      summary,
      data: detail
    });

    const enforcementText=!enforcing
      ?"Audit onlyのため記録のみ行い、自動処置は実行しません。"
      :protectedHumanOperator
        ? lockdown
          ?"人間管理者はBotより上位の保護対象です。本人へのKick/BAN/Timeout/ロール剥奪は行わず、破壊継続を止めるためLockdownのみ実行します。"
          :"人間管理者はBotより上位の保護対象です。設定の巻き戻しや本人への自動制裁は行わず、記録・通知のみ行います。"
        :actorHierarchyUnknown
          ? lockdown
            ?"実行者の階層を確認できないため個人制裁・設定巻き戻しを保留し、Lockdownのみ実行します。"
            :"実行者の階層を確認できないため個人制裁・設定巻き戻しを保留します。"
          :sanctionActor&&lockdown
            ?"実行者の隔離とLockdownを実行します。"
            :sanctionActor
              ?"実行者を隔離します。"
              :lockdown
                ?"対象への局所的な対処とLockdownを実行します。"
                :"対象への局所的な対処のみ実行し、実行者の隔離やLockdownは行いません。";
    await sendSecurityLog(
      this.env,
      guildId,
      settings,
      "Security Incident",
      `<@${actorId}> の **${spec.key}** を検知しました。\n` +
      enforcementText,
      true
    );

    if (sanctionActor) {
      await this.sanction(guildId, actorId, settings, spec.key);
    }

    if (lockdown && settings.response.autoLockdown && settings.mode === "enforce") {
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

  async handleAudit(
    entry: AuditEntry,
    options: { advanceCursor?: boolean } = {}
  ): Promise<void> {
    const guildId = entry.guild_id;
    if (!guildId || !entry.id) return;
    if (!(await claimAuditEntry(this.env, guildId, entry.id))) return;
    if (options.advanceCursor !== false) {
      await advanceAuditCursor(this.env, guildId, entry.id);
    }

    const actorId = entry.user_id ?? "";
    if (!actorId) return;

    const settings = await this.settings(guildId);
    if (!settings.enabled) return;

    // Safety Baseline is policy, not an Anti-Nuke exemption. Even a trusted
    // moderator lowering the server's explicit-media or verification setting
    // is corrected while the baseline is enabled.
    if (
      entry.action_type === 1 &&
      entry.changes?.some(change =>
        change.key === "explicit_content_filter" ||
        change.key === "verification_level"
      )
    ) {
      await enforceGuildSafetyBaseline(this.env, guildId, settings)
        .catch(error => console.error("safety baseline enforcement failed", guildId, error));
    }

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
    const actionAtMs = auditEntryCreatedAt(entry.id) ?? Date.now();
    if (
      await hasMaintenanceLease(
        this.env,
        guildId,
        actorId,
        spec.key,
        actionAtMs
      )
    ) return;

    if (
      spec.key === "bot_add" &&
      entry.target_id &&
      (
        isSecurityBotSelfTarget(this.env, entry.target_id) ||
        settings.allowedBotIds.includes(entry.target_id) ||
        entry.target_id === this.env.MAIN_BOT_APPLICATION_ID?.trim() ||
        await isManagedServiceBot(this.env, guildId, entry.target_id)
      )
    ) {
      return;
    }

    const actorBotState = await this.actorBotState(guildId, actorId, settings);
    const humanProtection = actorBotState.protectedBot
      ? "unprotected"
      : await this.humanOperatorProtection(guildId, actorId);
    const protectedHumanOperator = humanProtection === "protected";
    const actorHierarchyUnknown = humanProtection === "unknown";

    // Protected service bots are allowed to perform ordinary reversible
    // administration without feeding anti-nuke windows. Destructive actions
    // remain visible so a compromised service bot can still trigger Lockdown.
    if (
      actorBotState.protectedBot &&
      !isDestructiveAuditAction(spec.key)
    ) {
      return;
    }

    const thresholdValue = Number(settings.thresholds[spec.threshold]);
    const count = this.windowCount(
      guildId + ":" + actorId + ":" + spec.key,
      settings.thresholds.actionWindowSeconds
    );
    const profile = this.weightedProfile(
      guildId,
      actorId,
      spec,
      settings.thresholds.crossActionWindowSeconds
    );

    const pruneMembers = spec.key === "member_prune"
      ? Number(entry.options?.members_removed ?? 0)
      : 0;
    const securitySelfOverwrite =
      spec.key === "channel_overwrite" &&
      String(entry.options?.id ?? "") === this.env.DISCORD_APPLICATION_ID;
    const selfPrivilegeGrant =
      dangerousMemberRoles.length > 0 &&
      Boolean(entry.target_id) &&
      entry.target_id === actorId;
    const highRiskBotAdd =
      spec.key === "bot_add" &&
      Boolean(entry.target_id) &&
      await this.botHasDangerousPermissions(guildId,entry.target_id!);

    const decision=auditContainmentDecision({
      action:spec.key,
      count,
      thresholdValue,
      crossActionScore:profile.score,
      crossActionThreshold:settings.thresholds.crossActionScore,
      destructiveKinds:profile.destructiveKinds,
      securitySelfOverwrite,
      pruneMembers,
      highRiskBotAdd,
      selfPrivilegeGrant,
      actorIsBot: actorBotState.isBot
    });

    if (!decision.contain) {
      if(
        securitySelfOverwrite ||
        highRiskBotAdd ||
        selfPrivilegeGrant ||
        permissionChange.escalation
      ){
        await recordIncident(this.env,{
          guildId,
          actorId,
          kind:"security_review",
          severity:"medium",
          summary:"重要な管理操作を記録しました（証拠不足のため自動処置なし）",
          data:{
            auditEntryId:entry.id,
            actionType:entry.action_type,
            targetId:entry.target_id??null,
            actionCount:count,
            crossActionScore:profile.score,
            securitySelfOverwrite,
            highRiskBotAdd,
            selfPrivilegeGrant,
            permissionEscalation:permissionChange.escalation
          }
        });
      }
      return;
    }

    // Targeted remediation only happens after the high-confidence gate.
    if (
      !protectedHumanOperator &&
      !actorHierarchyUnknown &&
      permissionChange.escalation &&
      entry.target_id &&
      permissionChange.oldPermissions &&
      settings.mode === "enforce"
    ) {
      await rollbackRolePermissions(
        this.env,
        guildId,
        entry.target_id,
        permissionChange.oldPermissions
      ).catch(() => false);
    }

    if (
      !protectedHumanOperator &&
      !actorHierarchyUnknown &&
      dangerousMemberRoles.length &&
      entry.target_id &&
      settings.mode === "enforce"
    ) {
      for (const roleId of dangerousMemberRoles) {
        await botFetch(
          this.env,
          `/guilds/${guildId}/members/${entry.target_id}/roles/${roleId}`,
          {
            method: "DELETE",
            headers: {
              "X-Audit-Log-Reason": "Discord Security: high-confidence privilege escalation"
            }
          }
        ).catch(() => undefined);
      }
    }

    if (
      !protectedHumanOperator &&
      !actorHierarchyUnknown &&
      spec.key === "webhook" &&
      entry.action_type === 50 &&
      entry.target_id &&
      settings.mode === "enforce"
    ) {
      await deleteWebhook(this.env, entry.target_id).catch(() => false);
    }

    const sanctionActor =
      !actorBotState.protectedBot &&
      !protectedHumanOperator &&
      !actorHierarchyUnknown &&
      shouldAutoSanctionActor({
        action:spec.key,
        count,
        thresholdValue,
        crossActionScore:profile.score,
        crossActionThreshold:settings.thresholds.crossActionScore,
        destructiveKinds:profile.destructiveKinds,
        actorIsBot:actorBotState.isBot
      });
    await this.trigger(guildId, actorId, settings, spec, {
      auditEntryId: entry.id,
      actionType: entry.action_type,
      targetId: entry.target_id ?? null,
      actionCount: count,
      crossActionScore: profile.score,
      destructiveKinds:profile.destructiveKinds,
      membersRemoved: pruneMembers || undefined,
      securitySelfOverwrite,
      highRiskBotAdd,
      selfPrivilegeGrant,
      actorIsBot: actorBotState.isBot,
      protectedBotActor: actorBotState.protectedBot,
      protectedHumanOperator,
      actorHierarchyUnknown
    },
    sanctionActor,
    decision.lockdown && (!protectedHumanOperator || isDestructiveAuditAction(spec.key)),
    protectedHumanOperator,
    actorHierarchyUnknown);
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

    const accountAge = now - snowflakeCreatedAt(event.user.id);
    const tooYoung =
      accountAge >= 0 &&
      accountAge < settings.thresholds.minAccountAgeHours * 60 * 60_000;
    const youngHistory=(this.youngJoinWindows.get(event.guild_id)??[])
      .filter(at=>now-at<=windowMs);
    if(tooYoung) youngHistory.push(now);
    this.youngJoinWindows.set(event.guild_id,youngHistory);

    const confidence=raidConfidence({
      joins:history.length,
      youngJoins:youngHistory.length,
      raidJoins:settings.thresholds.raidJoins
    });
    const suspicionLogReady=
      (this.raidSuspicionLogUntil.get(event.guild_id)??0)<=now;

    if(confidence.suspicious&&suspicionLogReady){
      this.raidSuspicionLogUntil.set(
        event.guild_id,
        now + settings.thresholds.raidWindowSeconds * 1000
      );
      await recordIncident(this.env,{
        guildId:event.guild_id,
        actorId:null,
        kind:confidence.confirmed?"raid":"raid_suspected",
        severity:confidence.confirmed?"critical":"medium",
        summary:
          `${settings.thresholds.raidWindowSeconds}秒で${history.length}人の参加を検知`+
          `（新規アカウント ${youngHistory.length}人）`,
        data:{joins:history.length,youngJoins:youngHistory.length}
      });
      await sendSecurityLog(
        this.env,
        event.guild_id,
        settings,
        confidence.confirmed?"Raid confirmed":"Raid suspected",
        `${settings.thresholds.raidWindowSeconds}秒以内に${history.length}人が参加しました。`+
        ` 新規アカウント: **${youngHistory.length}**`,
        confidence.confirmed
      );
    }

    if(confidence.confirmed){
      this.raidModeUntil.set(
        event.guild_id,
        now + settings.response.lockdownMinutes * 60_000
      );
      if((this.raidLockdownUntil.get(event.guild_id)??0)<=now){
        this.raidLockdownUntil.set(
          event.guild_id,
          now + settings.response.lockdownMinutes * 60_000
        );
        if(settings.mode==="enforce"&&settings.response.autoLockdown){
          await enterLockdown(
            this.env,
            event.guild_id,
            settings.response.lockdownMinutes,
            "confirmed join raid"
          ).catch(() => false);
        }
      }
    }

    const raidActive = (this.raidModeUntil.get(event.guild_id) ?? 0) > now;
    if (
      settings.mode === "enforce" &&
      settings.response.quarantineRaidJoins &&
      raidActive &&
      tooYoung
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

  private severeContentActors(
    guildId: string,
    userId: string,
    seconds: number
  ): number {
    const now = Date.now();
    const history = (this.severeContentWindows.get(guildId) ?? [])
      .filter(item => now - item.at <= seconds * 1000);
    history.push({ at: now, userId });
    this.severeContentWindows.set(guildId, history);
    return new Set(history.map(item => item.userId)).size;
  }

  private async maybeContainContentOutbreak(
    guildId: string,
    userId: string,
    settings: SecuritySettings,
    violation: string
  ): Promise<void> {
    if (violation !== "phishing_url" && violation !== "dangerous_attachment") {
      return;
    }
    const distinctActors = this.severeContentActors(
      guildId,
      userId,
      settings.thresholds.severeContentWindowSeconds
    );
    if (distinctActors < settings.thresholds.severeContentUsers) return;

    const now = Date.now();
    if ((this.contentOutbreakCooldown.get(guildId) ?? 0) > now) return;
    this.contentOutbreakCooldown.set(
      guildId,
      now + settings.thresholds.severeContentWindowSeconds * 1000
    );

    await recordIncident(this.env, {
      guildId,
      actorId: null,
      kind: "content_outbreak",
      severity: "critical",
      summary:
        `${settings.thresholds.severeContentWindowSeconds}秒以内に` +
        `${distinctActors}人から重大な危険投稿を検知`,
      data: {
        distinctActors,
        trigger: violation
      }
    });

    await sendSecurityLog(
      this.env,
      guildId,
      settings,
      "Coordinated Content Attack",
      `複数アカウントによる重大な危険投稿を検知しました。\n` +
      `Actors: **${distinctActors}** / Window: **${settings.thresholds.severeContentWindowSeconds}s**`,
      true
    );

    if (settings.mode === "enforce" && settings.response.autoLockdown) {
      await enterLockdown(
        this.env,
        guildId,
        settings.response.lockdownMinutes,
        "coordinated content attack"
      ).catch(() => false);
    }
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

    let timeoutMinutes:number|null=null;
    let deleteUnsafe=false;

    if (settings.modules.antiSpam) {
      const count = this.messageWindow(
        this.messageWindows,
        userKey,
        settings.thresholds.spamWindowSeconds
      );
      const repeatedCount=this.repeatedMessageCount(
        userKey,
        settings.thresholds.spamWindowSeconds,
        event.content??""
      );
      const mentions =
        (event.mentions?.length ?? 0) + (event.mention_roles?.length ?? 0);
      if(isStrongSpam({
        messageCount:count,
        repeatedCount,
        mentions,
        spamMessages:settings.thresholds.spamMessages,
        mentionLimit:settings.thresholds.mentionLimit
      })){
        violation="spam";
        metadata={messageCount:count,repeatedCount,mentions};
        deleteUnsafe=true;
        timeoutMinutes=5;
      }
    }

    const urls = extractUrls(event.content ?? "");
    if (!violation && settings.modules.antiPhishing && urls.length) {
      const scored=urls.map(url=>({
        domain:url.hostname.toLowerCase(),
        score:scoreUrl(url,settings)
      }));
      const maxRisk=scored.reduce((max,item)=>Math.max(max,item.score),0);
      const linkCount = this.messageWindow(
        this.linkWindows,
        userKey,
        settings.thresholds.linkWindowSeconds
      );
      if(maxRisk>=80){
        violation="phishing_url";
        metadata={
          domains:[...new Set(scored.map(item=>item.domain))].slice(0,10),
          maxRisk,
          linkCount
        };
        deleteUnsafe=true;
        timeoutMinutes=settings.response.timeoutMinutes;
      }else if(
        linkCount>=Math.max(settings.thresholds.linkBurst*3,10)
      ){
        violation="link_burst";
        metadata={
          domains:[...new Set(scored.map(item=>item.domain))].slice(0,10),
          maxRisk,
          linkCount
        };
        deleteUnsafe=true;
        timeoutMinutes=5;
      }else if(maxRisk>=50){
        // Ambiguous links are recorded for review, never punished automatically.
        await recordIncident(this.env,{
          guildId,
          actorId:event.author.id,
          kind:"suspicious_link",
          severity:"low",
          summary:"不審リンクを記録しました（自動処置なし）",
          data:{
            domains:[...new Set(scored.map(item=>item.domain))].slice(0,10),
            maxRisk
          }
        });
      }
    }

    if (!violation && settings.modules.dangerousAttachments) {
      const risky=(event.attachments??[])
        .map(item=>({
          filename:String(item.filename??"unknown"),
          risk:attachmentRisk(item.filename)
        }))
        .filter(item=>item.risk);
      const high=risky.filter(item=>item.risk==="high");
      const review=risky.filter(item=>item.risk==="review");

      if(high.length){
        const attachmentCount=this.messageWindow(
          this.attachmentWindows,
          userKey,
          60
        );
        const deceptive=high.some(item=>
          deceptiveExecutableFilename(item.filename)
        );
        if(attachmentCount>=2||deceptive){
          violation="dangerous_attachment";
          metadata={
            filenames:high.map(item=>item.filename).slice(0,10),
            attachmentCount,
            deceptiveFilename:deceptive
          };
          deleteUnsafe=true;
          // Repeated executable delivery is a stronger malicious signal than
          // a single deceptive filename, so only repetition causes a timeout.
          timeoutMinutes=attachmentCount>=2
            ?settings.response.timeoutMinutes
            :null;
        }else{
          await recordIncident(this.env,{
            guildId,
            actorId:event.author.id,
            kind:"suspicious_attachment",
            severity:"low",
            summary:"実行可能な添付を記録しました（初回は自動処置なし）",
            data:{filenames:high.map(item=>item.filename).slice(0,10)}
          });
        }
      }else if(review.length){
        await recordIncident(this.env,{
          guildId,
          actorId:event.author.id,
          kind:"suspicious_attachment",
          severity:"low",
          summary:"実行可能性のある添付を記録しました（自動処置なし）",
          data:{filenames:review.map(item=>item.filename).slice(0,10)}
        });
      }
    }

    if (!violation) return;

    await recordIncident(this.env, {
      guildId,
      actorId: event.author.id,
      kind: violation,
      severity: violation === "spam" || violation === "link_burst" ? "medium" : "high",
      summary: `高信頼度の危険投稿を検知しました: ${violation}`,
      data: metadata
    });

    if (settings.mode === "enforce") {
      if (deleteUnsafe && settings.response.deleteUnsafeMessages) {
        await deleteMessage(this.env, event.channel_id, event.id).catch(() => false);
      }
      if(timeoutMinutes!==null){
        await timeoutMember(
          this.env,
          guildId,
          event.author.id,
          timeoutMinutes
        ).catch(() => false);
      }
    }

    await sendSecurityLog(
      this.env,
      guildId,
      settings,
      "Message Security",
      `<@${event.author.id}> の投稿を **${violation}** と判定しました。\n` +
      (timeoutMinutes===null
        ?"投稿のみ遮断し、ユーザーへのTimeoutは行っていません。\n"
        :"高信頼度判定のため自動封じ込めを実行しました。\n")+
      "本文や添付ファイル本体はSecurity Logへ保存していません。",
      violation === "phishing_url" || violation === "dangerous_attachment"
    );

    await this.maybeContainContentOutbreak(
      guildId,
      event.author.id,
      settings,
      violation
    );
  }

  async reconcileGuild(guildId: string): Promise<void> {
    const settings = await this.settings(guildId);
    if (settings.enabled) {
      await enforceGuildSafetyBaseline(this.env, guildId, settings)
        .catch(error => console.error("scheduled safety baseline failed", guildId, error));
    }

    const cursor = await getAuditCursor(this.env, guildId);
    const backlog = await fetchAuditBacklog(this.env, guildId, cursor, 10);
    if (!backlog.newestId) return;

    // First sight of a guild establishes a baseline instead of punishing
    // historical legitimate admin actions performed before Security connected.
    if (!cursor) {
      await advanceAuditCursor(this.env, guildId, backlog.newestId);
      return;
    }

    if (backlog.truncated && settings.enabled) {
      await recordIncident(this.env, {
        guildId,
        actorId: null,
        kind: "audit_backlog_truncated",
        severity: "critical",
        summary: "Gateway切断中の監査ログが1000件を超えたため緊急封じ込めを実行",
        data: {
          pages: backlog.pages,
          collectedEntries: backlog.entries.length
        }
      });
      await sendSecurityLog(
        this.env,
        guildId,
        settings,
        "Audit Backlog Overflow",
        "Gateway切断中の監査ログが追跡上限を超えました。未確認の管理操作が残る可能性があるため、安全側へ倒します。",
        true
      );
      // Missing audit history is an observability problem, not proof of an
      // attack. Never lock a guild solely because the backlog exceeded the
      // reconciliation window; wait for concrete hostile evidence.

    }

    const fresh = [...backlog.entries].reverse();
    for (const entry of fresh) {
      await this.handleAudit(entry, { advanceCursor: false });
    }

    if (backlog.fetchFailed) {
      // Do not move the durable cursor past entries we never fetched.
      // Already-processed entries are deduplicated by processed_audit_entries,
      // so the next reconciliation can safely fetch the same newest pages and
      // continue deeper once Discord's Audit Log API recovers.
      console.warn(
        "audit reconciliation incomplete; cursor retained",
        guildId,
        { pages: backlog.pages, collectedEntries: backlog.entries.length }
      );
      return;
    }

    await advanceAuditCursor(this.env, guildId, backlog.newestId);
  }

}
