import type {
  Env,
  GuildSafetyStatus,
  SecurityCapabilities,
  SecuritySettings
} from "./types";
import {
  deleteLockdownSnapshot,
  getLockdownSnapshot,
  getSecuritySettings,
  listManagedServiceBots,
  putLockdownSnapshot
} from "./db";

export class DiscordApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string
  ) {
    super(`Discord API ${status}: ${body.slice(0, 300)}`);
  }
}

export async function botFetch(
  env: Env,
  path: string,
  init: RequestInit = {},
  retry = true
): Promise<Response> {
  const response = await fetch(`https://discord.com/api/v10${path}`, {
    ...init,
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {})
    }
  });
  if (response.status === 429 && retry) {
    const body = await response.clone().json().catch(() => ({})) as {
      retry_after?: number;
    };
    const delay = Math.min(5000, Math.max(250, Number(body.retry_after ?? 1) * 1000));
    await new Promise(resolve => setTimeout(resolve, delay));
    return botFetch(env, path, init, false);
  }
  return response;
}

export async function botJson<T>(
  env: Env,
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const response = await botFetch(env, path, init);
  if (!response.ok) {
    throw new DiscordApiError(response.status, await response.text());
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

type DiscordGuildSafety = {
  explicit_content_filter?: number;
  verification_level?: number;
  mfa_level?: number;
  features?: string[];
  safety_alerts_channel_id?: string | null;
};

function safetyStatusFromGuild(
  guild: DiscordGuildSafety,
  settings: SecuritySettings
): GuildSafetyStatus {
  const explicitContentFilter = Number(guild.explicit_content_filter ?? 0);
  const verificationLevel = Number(guild.verification_level ?? 0);
  const minimumVerificationLevel = Math.max(
    0,
    Math.min(4, Math.trunc(settings.safety.minimumVerificationLevel))
  );
  return {
    explicitContentFilter,
    verificationLevel,
    mfaLevel: Number(guild.mfa_level ?? 0),
    raidAlertsEnabled: !(guild.features ?? []).includes("RAID_ALERTS_DISABLED"),
    safetyAlertsChannelConfigured: Boolean(guild.safety_alerts_channel_id),
    baselineReady:
      (!settings.safety.enforceExplicitContentFilter || explicitContentFilter >= 2) &&
      verificationLevel >= minimumVerificationLevel
  };
}

export async function getGuildSafetyStatus(
  env: Env,
  guildId: string,
  settings: SecuritySettings
): Promise<GuildSafetyStatus> {
  const guild = await botJson<DiscordGuildSafety>(
    env,
    `/guilds/${guildId}`
  );
  return safetyStatusFromGuild(guild, settings);
}

export async function enforceGuildSafetyBaseline(
  env: Env,
  guildId: string,
  settings: SecuritySettings
): Promise<GuildSafetyStatus> {
  let guild = await botJson<DiscordGuildSafety>(env, `/guilds/${guildId}`);
  const patch: Record<string, number> = {};
  const currentFilter = Number(guild.explicit_content_filter ?? 0);
  const currentVerification = Number(guild.verification_level ?? 0);
  const minimumVerification = Math.max(
    0,
    Math.min(4, Math.trunc(settings.safety.minimumVerificationLevel))
  );

  if (
    settings.safety.enforceExplicitContentFilter &&
    currentFilter < 2
  ) patch.explicit_content_filter = 2;

  if (currentVerification < minimumVerification) {
    patch.verification_level = minimumVerification;
  }

  if (Object.keys(patch).length) {
    guild = await botJson<DiscordGuildSafety>(env, `/guilds/${guildId}`, {
      method: "PATCH",
      headers: {
        "X-Audit-Log-Reason": "Discord Security: enforce server safety baseline"
      },
      body: JSON.stringify(patch)
    });
  }

  return safetyStatusFromGuild(guild, settings);
}

export async function sendSecurityLog(
  env: Env,
  guildId: string,
  settings: SecuritySettings,
  title: string,
  description: string,
  critical = false
): Promise<void> {
  if (!settings.logChannelId) return;
  const body = {
    allowed_mentions: { parse: [] },
    embeds: [{
      title,
      description: description.slice(0, 3500),
      color: critical ? 0xed4245 : 0xfee75c,
      footer: { text: `Guild ${guildId}` },
      timestamp: new Date().toISOString()
    }]
  };
  await botFetch(env, `/channels/${settings.logChannelId}/messages`, {
    method: "POST",
    body: JSON.stringify(body)
  }).catch(() => undefined);
}

const DANGEROUS_PERMISSION_BITS = [
  1n << 1n,  // Kick Members
  1n << 2n,  // Ban Members
  1n << 3n,  // Administrator
  1n << 4n,  // Manage Channels
  1n << 5n,  // Manage Guild
  1n << 28n, // Manage Roles
  1n << 29n, // Manage Webhooks
  1n << 40n  // Moderate Members
];

export function containsDangerousPermission(value: string | number | bigint): boolean {
  let bits: bigint;
  try {
    bits = BigInt(value);
  } catch {
    return false;
  }
  return DANGEROUS_PERMISSION_BITS.some(bit => (bits & bit) === bit);
}

export function dangerousPermissionAdded(
  oldValue: unknown,
  newValue: unknown
): boolean {
  try {
    const before = BigInt(String(oldValue ?? "0"));
    const after = BigInt(String(newValue ?? "0"));
    const added = after & ~before;
    return DANGEROUS_PERMISSION_BITS.some(bit => (added & bit) === bit);
  } catch {
    return false;
  }
}

export function isHierarchyRelevantDangerousRole(
  role: { id: string; permissions: string; managed?: boolean },
  selfRoleIds: ReadonlySet<string>
): boolean {
  // Managed bot/integration roles cannot be stripped by Security and should not
  // force Security above every service bot. Human-editable dangerous roles are
  // still reported for hierarchy diagnostics, but roles intentionally placed
  // above Security are treated as human-operator territory rather than a
  // readiness failure.
  return (
    !role.managed &&
    !selfRoleIds.has(role.id) &&
    containsDangerousPermission(role.permissions)
  );
}

type DiscordRole = {
  id: string;
  name?: string;
  permissions: string;
  managed?: boolean;
  position?: number;
};

type DiscordMember = {
  user?: { id: string; bot?: boolean };
  roles?: string[];
};

export async function getGuildOwnerId(env: Env, guildId: string): Promise<string | null> {
  const guild = await botJson<{ owner_id?: string }>(env, `/guilds/${guildId}`).catch(() => null);
  return guild?.owner_id ?? null;
}

export async function getMember(
  env: Env,
  guildId: string,
  userId: string
): Promise<DiscordMember | null> {
  return await botJson<DiscordMember>(
    env,
    `/guilds/${guildId}/members/${userId}`
  ).catch(() => null);
}

const CAPABILITY_PERMISSIONS = [
  ["View Audit Log", 1n << 7n],
  ["View Channels", 1n << 10n],
  ["Manage Channels", 1n << 4n],
  ["Manage Roles", 1n << 28n],
  ["Manage Webhooks", 1n << 29n],
  ["Manage Messages", 1n << 13n],
  ["Moderate Members", 1n << 40n],
  ["Kick Members", 1n << 1n],
  ["Ban Members", 1n << 2n]
] as const;

function memberBasePermissions(
  guildId: string,
  member: DiscordMember,
  roles: DiscordRole[]
): bigint {
  let permissions = BigInt(
    roles.find(role => role.id === guildId)?.permissions ?? "0"
  );
  for (const roleId of member.roles ?? []) {
    const role = roles.find(item => item.id === roleId);
    if (role) permissions |= BigInt(role.permissions || "0");
  }
  return permissions;
}

export function roleIsStrictlyAbove(
  upper: { position?: number; id?: string },
  lower: { position?: number; id?: string }
): boolean {
  const upperPosition = Number(upper.position ?? 0);
  const lowerPosition = Number(lower.position ?? 0);
  if (upperPosition !== lowerPosition) return upperPosition > lowerPosition;

  // Discord can report equal numeric positions. Match Discord's role
  // hierarchy tie-breaker used by the Main Bot: the older/smaller snowflake
  // is considered higher for equal positions.
  if (!upper.id || !lower.id || upper.id === lower.id) return false;
  try {
    return BigInt(upper.id) < BigInt(lower.id);
  } catch {
    return false;
  }
}

function highestMemberRole(
  member: DiscordMember | null,
  roles: DiscordRole[]
): DiscordRole | null {
  if (!member?.roles?.length) return null;
  return roles
    .filter(role => member.roles!.includes(role.id))
    .sort((a, b) => {
      const position = Number(b.position ?? 0) - Number(a.position ?? 0);
      if (position !== 0) return position;
      try {
        return BigInt(a.id) < BigInt(b.id) ? 1 : -1;
      } catch {
        return 0;
      }
    })[0] ?? null;
}

export function humanMemberOutranksSecurity(
  member: DiscordMember | null,
  securityMember: DiscordMember | null,
  roles: DiscordRole[]
): boolean {
  if (!member || member.user?.bot || !securityMember) return false;
  const humanHighest = highestMemberRole(member, roles);
  const securityHighest = highestMemberRole(securityMember, roles);
  return Boolean(
    humanHighest &&
    securityHighest &&
    roleIsStrictlyAbove(humanHighest, securityHighest)
  );
}

export async function humanMemberOutranksSecurityById(
  env: Env,
  guildId: string,
  userId: string
): Promise<boolean | null> {
  const [roles, securityMember, member] = await Promise.all([
    botJson<DiscordRole[]>(env, `/guilds/${guildId}/roles`).catch(() => []),
    getMember(env, guildId, env.DISCORD_APPLICATION_ID),
    getMember(env, guildId, userId)
  ]);
  if (!roles.length || !securityMember || !member) return null;
  if (member.user?.bot) return false;
  return humanMemberOutranksSecurity(member, securityMember, roles);
}

export async function getSecurityCapabilities(
  env: Env,
  guildId: string,
  managedBotIds: string[] = []
): Promise<SecurityCapabilities> {
  const [roles, self] = await Promise.all([
    botJson<DiscordRole[]>(env, `/guilds/${guildId}/roles`).catch(() => []),
    getMember(env, guildId, env.DISCORD_APPLICATION_ID)
  ]);
  if (!self || !roles.length) {
    return {
      administrator: false,
      requiredReady: false,
      maximumProtection: false,
      roleAboveManagedBots: null,
      roleAboveDangerousRoles: null,
      dangerousRolesNotBelow: [],
      highestRoleName: null,
      highestRolePosition: null,
      missingPermissions: CAPABILITY_PERMISSIONS.map(([name]) => name)
    };
  }

  const permissions = memberBasePermissions(guildId, self, roles);
  const administrator = (permissions & (1n << 3n)) !== 0n;
  const missingPermissions = administrator
    ? []
    : CAPABILITY_PERMISSIONS
        .filter(([, bit]) => (permissions & bit) !== bit)
        .map(([name]) => name);

  const selfHighest = highestMemberRole(self, roles);
  const managedMembers = await Promise.all(
    managedBotIds.map(id => getMember(env, guildId, id))
  );
  const installedManagedHighest = managedMembers
    .map(member => highestMemberRole(member, roles))
    .filter((role): role is DiscordRole => Boolean(role));

  let roleAboveManagedBots: boolean | null = null;
  if (installedManagedHighest.length && selfHighest) {
    roleAboveManagedBots = installedManagedHighest.every(role =>
      roleIsStrictlyAbove(selfHighest, role)
    );
  }

  const selfRoleIds = new Set(self.roles ?? []);
  const dangerousRoles = roles.filter(role =>
    isHierarchyRelevantDangerousRole(role, selfRoleIds)
  );
  const dangerousRolesNotBelow = dangerousRoles
    .filter(role => !selfHighest || !roleIsStrictlyAbove(selfHighest, role))
    .map(role => ({
      id: role.id,
      name: role.name ?? role.id,
      position: Number(role.position ?? 0)
    }))
    .sort((a, b) => b.position - a.position)
    .slice(0, 20);
  const roleAboveDangerousRoles = selfHighest
    ? dangerousRolesNotBelow.length === 0
    : null;
  // Role hierarchy is deliberately not a readiness gate. Human administrators
  // are expected to sit above every bot. Security protects the server below its
  // own hierarchy boundary and never requires authority over those operators.
  // The diagnostic fields are retained so the dashboard can explain which roles
  // are intentionally outside Security's automatic moderation boundary.

  return {
    administrator,
    requiredReady: missingPermissions.length === 0,
    // "Maximum" means the Security Bot itself has Administrator and therefore
    // cannot be channel-overwrite locked out. It still does not outrank human
    // administrators by design.
    maximumProtection: administrator,
    roleAboveManagedBots,
    roleAboveDangerousRoles,
    dangerousRolesNotBelow,
    highestRoleName: selfHighest?.name ?? null,
    highestRolePosition: selfHighest?.position ?? null,
    missingPermissions
  };
}

export async function stripDangerousRoles(
  env: Env,
  guildId: string,
  userId: string
): Promise<number> {
  const [member, roles] = await Promise.all([
    getMember(env, guildId, userId),
    botJson<DiscordRole[]>(env, `/guilds/${guildId}/roles`).catch(() => [])
  ]);
  if (!member?.roles?.length) return 0;
  const dangerous = roles.filter(role =>
    member.roles!.includes(role.id) &&
    !role.managed &&
    containsDangerousPermission(role.permissions)
  );
  let removed = 0;
  for (const role of dangerous) {
    const response = await botFetch(
      env,
      `/guilds/${guildId}/members/${userId}/roles/${role.id}`,
      {
        method: "DELETE",
        headers: { "X-Audit-Log-Reason": "Discord Security: dangerous action containment" }
      }
    );
    if (response.ok) removed++;
  }
  return removed;
}

export async function timeoutMember(
  env: Env,
  guildId: string,
  userId: string,
  minutes: number
): Promise<boolean> {
  const until = new Date(Date.now() + Math.max(1, Math.min(40320, minutes)) * 60_000)
    .toISOString();
  const response = await botFetch(env, `/guilds/${guildId}/members/${userId}`, {
    method: "PATCH",
    headers: { "X-Audit-Log-Reason": "Discord Security automated containment" },
    body: JSON.stringify({ communication_disabled_until: until })
  });
  return response.ok;
}

export async function kickMember(
  env: Env,
  guildId: string,
  userId: string,
  reason: string
): Promise<boolean> {
  const response = await botFetch(env, `/guilds/${guildId}/members/${userId}`, {
    method: "DELETE",
    headers: { "X-Audit-Log-Reason": reason }
  });
  return response.ok;
}

export async function deleteMessage(
  env: Env,
  channelId: string,
  messageId: string
): Promise<boolean> {
  const response = await botFetch(env, `/channels/${channelId}/messages/${messageId}`, {
    method: "DELETE"
  });
  return response.ok;
}

export async function deleteWebhook(
  env: Env,
  webhookId: string
): Promise<boolean> {
  const response = await botFetch(env, `/webhooks/${webhookId}`, {
    method: "DELETE",
    headers: { "X-Audit-Log-Reason": "Discord Security: unauthorized webhook" }
  });
  return response.ok;
}

export async function rollbackRolePermissions(
  env: Env,
  guildId: string,
  roleId: string,
  oldPermissions: string
): Promise<boolean> {
  const response = await botFetch(env, `/guilds/${guildId}/roles/${roleId}`, {
    method: "PATCH",
    headers: { "X-Audit-Log-Reason": "Discord Security: permission escalation rollback" },
    body: JSON.stringify({ permissions: oldPermissions })
  });
  return response.ok;
}

type DiscordOverwrite = {
  id: string;
  type: number;
  allow: string;
  deny: string;
};

type DiscordChannel = {
  id: string;
  type: number;
  parent_id?: string | null;
  permission_overwrites?: DiscordOverwrite[];
};

const SEND_MESSAGES = 1n << 11n;
const ADD_REACTIONS = 1n << 6n;
const CONNECT = 1n << 20n;
const SPEAK = 1n << 21n;
const CREATE_PUBLIC_THREADS = 1n << 35n;
const CREATE_PRIVATE_THREADS = 1n << 36n;
const SEND_MESSAGES_IN_THREADS = 1n << 38n;
const LOCKDOWN_DENY =
  SEND_MESSAGES |
  ADD_REACTIONS |
  CONNECT |
  SPEAK |
  CREATE_PUBLIC_THREADS |
  CREATE_PRIVATE_THREADS |
  SEND_MESSAGES_IN_THREADS;

type LockdownBypass = {
  roleIds?: Iterable<string>;
  memberIds?: Iterable<string>;
};

export function lockdownOperatorMemberIds(input: {
  trustedUserIds?: Iterable<string>;
  allowedBotIds?: Iterable<string>;
  managedBotIds?: Iterable<string>;
  ownerId?: string | null;
  securityBotId?: string | null;
  mainBotId?: string | null;
}): Set<string> {
  const ids = new Set<string>();
  for (const id of input.trustedUserIds ?? []) if (id) ids.add(id);
  for (const id of input.allowedBotIds ?? []) if (id) ids.add(id);
  for (const id of input.managedBotIds ?? []) if (id) ids.add(id);
  if (input.ownerId) ids.add(input.ownerId);
  if (input.securityBotId) ids.add(input.securityBotId);
  if (input.mainBotId) ids.add(input.mainBotId);
  return ids;
}

export function buildLockdownOverwrites(
  guildId: string,
  current: DiscordOverwrite[],
  bypass: LockdownBypass = {}
): DiscordOverwrite[] {
  const bypassRoles = new Set(bypass.roleIds ?? []);
  const bypassMembers = new Set(bypass.memberIds ?? []);

  const next = current.map(item => {
    const isBypass =
      (item.type === 0 && bypassRoles.has(item.id)) ||
      (item.type === 1 && bypassMembers.has(item.id));
    const allow = isBypass
      ? BigInt(item.allow || "0") | LOCKDOWN_DENY
      : BigInt(item.allow || "0") & ~LOCKDOWN_DENY;
    const deny = isBypass
      ? BigInt(item.deny || "0") & ~LOCKDOWN_DENY
      : BigInt(item.deny || "0") | LOCKDOWN_DENY;
    return {
      id: item.id,
      type: item.type,
      allow: allow.toString(),
      deny: deny.toString()
    };
  });

  if (!next.some(item => item.id === guildId && item.type === 0)) {
    next.push({
      id: guildId,
      type: 0,
      allow: "0",
      deny: LOCKDOWN_DENY.toString()
    });
  }

  for (const roleId of bypassRoles) {
    if (!roleId || roleId === guildId) continue;
    if (!next.some(item => item.id === roleId && item.type === 0)) {
      next.push({
        id: roleId,
        type: 0,
        allow: LOCKDOWN_DENY.toString(),
        deny: "0"
      });
    }
  }
  for (const memberId of bypassMembers) {
    if (!memberId) continue;
    if (!next.some(item => item.id === memberId && item.type === 1)) {
      next.push({
        id: memberId,
        type: 1,
        allow: LOCKDOWN_DENY.toString(),
        deny: "0"
      });
    }
  }
  return next;
}

function canonicalOverwrites(items: DiscordOverwrite[]): string {
  return JSON.stringify(
    [...items]
      .map(item => ({
        id: item.id,
        type: item.type,
        allow: String(item.allow || "0"),
        deny: String(item.deny || "0")
      }))
      .sort((a, b) =>
        a.type !== b.type ? a.type - b.type : a.id.localeCompare(b.id)
      )
  );
}

export async function patchChannelOverwrites(
  env: Env,
  channelId: string,
  permissionOverwrites: DiscordOverwrite[],
  reason: string
): Promise<void> {
  await botJson<DiscordChannel>(env, `/channels/${channelId}`, {
    method: "PATCH",
    headers: { "X-Audit-Log-Reason": reason },
    body: JSON.stringify({ permission_overwrites: permissionOverwrites })
  });
}

const MAIN_BOT_CHANNEL_RECOVERY_MASK =
  (1n << 4n) |
  (1n << 10n) |
  (1n << 11n) |
  (1n << 13n) |
  (1n << 14n) |
  (1n << 15n) |
  (1n << 16n) |
  (1n << 28n);

export function buildManagedBotRecoveryOverwrites(
  current: DiscordOverwrite[],
  botId: string
): DiscordOverwrite[] {
  const existing = current.find(item => item.id === botId && item.type === 1);
  let allow = BigInt(existing?.allow ?? "0");
  let deny = BigInt(existing?.deny ?? "0");
  allow |= MAIN_BOT_CHANNEL_RECOVERY_MASK;
  deny &= ~MAIN_BOT_CHANNEL_RECOVERY_MASK;

  return [
    ...current
      .filter(item => !(item.id === botId && item.type === 1))
      .map(item => ({
        id: item.id,
        type: item.type,
        allow: String(item.allow || "0"),
        deny: String(item.deny || "0")
      })),
    {
      id: botId,
      type: 1,
      allow: allow.toString(),
      deny: deny.toString()
    }
  ];
}

export async function repairManagedBotChannelAccess(
  env: Env,
  guildId: string,
  botId: string,
  channelId: string
): Promise<{ changed: boolean }> {
  const member = await getMember(env, guildId, botId);
  if (!member) {
    throw new DiscordApiError(404, "Main Bot is not a member of this guild");
  }

  const channels = await botJson<DiscordChannel[]>(
    env,
    `/guilds/${guildId}/channels`
  );
  const channel = channels.find(item => item.id === channelId);
  if (!channel) {
    throw new DiscordApiError(404, "Channel not found in guild");
  }

  const current = channel.permission_overwrites ?? [];
  const repaired = buildManagedBotRecoveryOverwrites(current, botId);
  if (canonicalOverwrites(current) === canonicalOverwrites(repaired)) {
    return { changed: false };
  }

  await patchChannelOverwrites(
    env,
    channelId,
    repaired,
    "Discord Security: repair Main Bot dashboard channel access"
  );
  return { changed: true };
}

export async function enterLockdown(
  env: Env,
  guildId: string,
  minutes: number,
  reason: string
): Promise<boolean> {
  const existing = await getLockdownSnapshot(env, guildId);
  if (existing) return false;

  const [channels, settings, roles, self, ownerId, managedBots] = await Promise.all([
    botJson<DiscordChannel[]>(env, `/guilds/${guildId}/channels`),
    getSecuritySettings(env, guildId),
    botJson<DiscordRole[]>(env, `/guilds/${guildId}/roles`).catch(() => []),
    getMember(env, guildId, env.DISCORD_APPLICATION_ID),
    getGuildOwnerId(env, guildId),
    listManagedServiceBots(env, guildId).catch(() => [])
  ]);

  const selfHighest = highestMemberRole(self, roles);
  const operatorRoleIds = new Set(settings.trustedRoleIds);
  if (selfHighest) {
    for (const role of roles) {
      if (
        role.id !== guildId &&
        !role.managed &&
        containsDangerousPermission(role.permissions) &&
        roleIsStrictlyAbove(role, selfHighest)
      ) {
        // Human privileged roles intentionally placed above Security Bot are
        // outside the bot's moderation hierarchy. Keep them usable as emergency
        // operators instead of silencing the people who must recover the guild.
        operatorRoleIds.add(role.id);
      }
    }
  }

  // Keep infrastructure bots usable during Lockdown. Main Bot's own access
  // guard otherwise restores its overwrite on the next sweep, causing the two
  // services to fight over the same channel permissions.
  const operatorMemberIds = lockdownOperatorMemberIds({
    trustedUserIds: settings.trustedUserIds,
    allowedBotIds: settings.allowedBotIds,
    managedBotIds: managedBots.map(bot => bot.botId),
    ownerId,
    securityBotId: env.DISCORD_APPLICATION_ID?.trim() || null,
    mainBotId: env.MAIN_BOT_APPLICATION_ID?.trim() || null
  });
  const categories = new Map(
    channels
      .filter(channel => channel.type === 4)
      .map(channel => [channel.id, channel] as const)
  );

  const targets = channels.filter(channel => {
    if (channel.type === 4) return true;
    if (![0, 2, 5, 13, 15, 16].includes(channel.type)) return false;
    if (!channel.parent_id) return true;
    const parent = categories.get(channel.parent_id);
    if (!parent) return true;
    return canonicalOverwrites(channel.permission_overwrites ?? []) !==
      canonicalOverwrites(parent.permission_overwrites ?? []);
  });

  const snapshot = targets.map(channel => ({
    channelId: channel.id,
    permissionOverwrites: (channel.permission_overwrites ?? []).map(item => ({
      id: item.id,
      type: item.type,
      allow: String(item.allow || "0"),
      deny: String(item.deny || "0")
    }))
  }));

  await putLockdownSnapshot(env, {
    guildId,
    reason,
    expiresAt: Date.now() + Math.max(1, Math.min(180, minutes)) * 60_000,
    createdAt: Date.now(),
    channels: snapshot
  });

  const applied: typeof snapshot = [];
  try {
    for (const item of snapshot) {
      const permissionOverwrites = buildLockdownOverwrites(
        guildId,
        item.permissionOverwrites,
        {
          roleIds: operatorRoleIds,
          memberIds: operatorMemberIds
        }
      );
      try {
        await patchChannelOverwrites(
          env,
          item.channelId,
          permissionOverwrites,
          `Discord Security Lockdown: ${reason}`
        );
        applied.push(item);
      } catch (error) {
        // If the channel disappeared between the guild snapshot and the PATCH,
        // there is nothing left to contain. Other failures are unsafe to hide.
        if (error instanceof DiscordApiError && error.status === 404) continue;
        throw error;
      }
    }
  } catch (error) {
    const rollbackFailures: string[] = [];
    for (const item of [...applied].reverse()) {
      try {
        await patchChannelOverwrites(
          env,
          item.channelId,
          item.permissionOverwrites,
          "Discord Security: rollback incomplete lockdown"
        );
      } catch (rollbackError) {
        if (
          rollbackError instanceof DiscordApiError &&
          rollbackError.status === 404
        ) continue;
        rollbackFailures.push(item.channelId);
      }
    }

    // Only discard the recovery snapshot when every applied change was
    // successfully rolled back. Otherwise keep it so manual/scheduled unlock
    // can retry and we never lose the original permission state.
    if (rollbackFailures.length === 0) {
      await deleteLockdownSnapshot(env, guildId);
    }
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(
      rollbackFailures.length
        ? `Lockdown failed and rollback is incomplete for ${rollbackFailures.length} channel(s): ${detail}`
        : `Lockdown failed and was rolled back safely: ${detail}`
    );
  }
  return true;
}

export async function exitLockdown(
  env: Env,
  guildId: string
): Promise<boolean> {
  const snapshot = await getLockdownSnapshot(env, guildId);
  if (!snapshot) return false;

  const failures: string[] = [];
  for (const item of snapshot.channels) {
    try {
      await patchChannelOverwrites(
        env,
        item.channelId,
        item.permissionOverwrites,
        "Discord Security Lockdown ended"
      );
    } catch (error) {
      // Deleted channels no longer need their permissions restored.
      if (error instanceof DiscordApiError && error.status === 404) continue;
      failures.push(item.channelId);
    }
  }

  if (failures.length) {
    // Keep the snapshot. The scheduled recovery sweep will retry next minute
    // and a dashboard unlock can also retry without losing the original state.
    throw new Error(
      `Lockdown restore incomplete for ${failures.length} channel(s)`
    );
  }

  await deleteLockdownSnapshot(env, guildId);
  return true;
}
