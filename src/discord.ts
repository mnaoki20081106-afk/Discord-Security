import type { Env, SecuritySettings } from "./types";
import {
  deleteLockdownSnapshot,
  getLockdownSnapshot,
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

type DiscordRole = {
  id: string;
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

type DiscordChannel = {
  id: string;
  type: number;
  permission_overwrites?: Array<{
    id: string;
    type: number;
    allow: string;
    deny: string;
  }>;
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

export async function enterLockdown(
  env: Env,
  guildId: string,
  minutes: number,
  reason: string
): Promise<boolean> {
  const existing = await getLockdownSnapshot(env, guildId);
  if (existing) return false;
  const channels = await botJson<DiscordChannel[]>(
    env,
    `/guilds/${guildId}/channels`
  );
  const snapshot = channels
    .filter(channel => [0, 2, 5, 13, 15, 16].includes(channel.type))
    .map(channel => {
      const overwrite = channel.permission_overwrites?.find(
        item => item.id === guildId && item.type === 0
      );
      return {
        channelId: channel.id,
        hadOverwrite: Boolean(overwrite),
        allow: overwrite?.allow ?? "0",
        deny: overwrite?.deny ?? "0"
      };
    });

  await putLockdownSnapshot(env, {
    guildId,
    reason,
    expiresAt: Date.now() + Math.max(1, Math.min(180, minutes)) * 60_000,
    createdAt: Date.now(),
    channels: snapshot
  });

  for (const item of snapshot) {
    const deny = (BigInt(item.deny) | LOCKDOWN_DENY).toString();
    await botFetch(env, `/channels/${item.channelId}/permissions/${guildId}`, {
      method: "PUT",
      headers: { "X-Audit-Log-Reason": `Discord Security Lockdown: ${reason}` },
      body: JSON.stringify({
        type: 0,
        allow: item.allow,
        deny
      })
    }).catch(() => undefined);
  }
  return true;
}

export async function exitLockdown(
  env: Env,
  guildId: string
): Promise<boolean> {
  const snapshot = await getLockdownSnapshot(env, guildId);
  if (!snapshot) return false;
  for (const item of snapshot.channels) {
    if (item.hadOverwrite) {
      await botFetch(env, `/channels/${item.channelId}/permissions/${guildId}`, {
        method: "PUT",
        headers: { "X-Audit-Log-Reason": "Discord Security Lockdown ended" },
        body: JSON.stringify({
          type: 0,
          allow: item.allow,
          deny: item.deny
        })
      }).catch(() => undefined);
    } else {
      await botFetch(env, `/channels/${item.channelId}/permissions/${guildId}`, {
        method: "DELETE",
        headers: { "X-Audit-Log-Reason": "Discord Security Lockdown ended" }
      }).catch(() => undefined);
    }
  }
  await deleteLockdownSnapshot(env, guildId);
  return true;
}
