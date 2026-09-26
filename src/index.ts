import {
  cleanExpired,
  consumeBridgeNonce,
  createMaintenanceLease,
  ensureSchema,
  getLockdownSnapshot,
  getSecuritySettings,
  listExpiredLockdowns,
  listIncidents,
  listManagedServiceBots,
  registerManagedServiceBot,
  saveSecuritySettings
} from "./db";
import {
  botJson,
  enterLockdown,
  exitLockdown,
  getSecurityCapabilities
} from "./discord";
import {
  DiscordSecurityGateway,
  ensureDiscordSecurityGateway,
  gatewayStatus,
  reconcileDiscordSecurityAudits
} from "./gateway";
import type {
  Env,
  MaintenanceScope,
  SecuritySettings
} from "./types";

export { DiscordSecurityGateway };

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)]
    .map(value => value.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacHex(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return hex(await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  ));
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index++) {
    diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return diff === 0;
}

async function verifyBridge(
  request: Request,
  env: Env,
  body: string
): Promise<boolean> {
  if (!env.SECURITY_BRIDGE_SECRET || env.SECURITY_BRIDGE_SECRET.length < 32) {
    return false;
  }
  const timestamp = request.headers.get("X-Security-Timestamp") ?? "";
  const nonce = request.headers.get("X-Security-Nonce") ?? "";
  const signature = request.headers.get("X-Security-Signature") ?? "";
  if (
    !/^\d+$/.test(timestamp) ||
    !/^[a-zA-Z0-9_-]{16,128}$/.test(nonce) ||
    !/^[a-f0-9]{64}$/i.test(signature)
  ) return false;
  const numeric = Number(timestamp);
  if (!Number.isFinite(numeric) || Math.abs(Date.now() - numeric) > 60_000) {
    return false;
  }
  const url = new URL(request.url);
  const canonical =
    timestamp + "\n" +
    nonce + "\n" +
    request.method.toUpperCase() + "\n" +
    url.pathname + url.search + "\n" +
    body;
  const expected = await hmacHex(env.SECURITY_BRIDGE_SECRET, canonical);
  if (!safeEqual(expected, signature.toLowerCase())) return false;
  return consumeBridgeNonce(env, nonce, Date.now() + 2 * 60_000);
}

async function invalidateGatewaySettings(env: Env, guildId: string): Promise<void> {
  const id = env.SECURITY_GATEWAY.idFromName("discord-security");
  await env.SECURITY_GATEWAY.get(id).fetch(
    "https://security-gateway.internal/invalidate/" + encodeURIComponent(guildId),
    { method: "POST" }
  ).catch(() => undefined);
}

function settingsPatch(body: unknown): Partial<SecuritySettings> {
  if (!body || typeof body !== "object") return {};
  const input = body as Partial<SecuritySettings>;
  const patch: Partial<SecuritySettings> = {};
  if (typeof input.enabled === "boolean") patch.enabled = input.enabled;
  if (input.mode === "audit" || input.mode === "enforce") patch.mode = input.mode;
  if (["balanced", "strict", "paranoid"].includes(String(input.profile))) {
    patch.profile = input.profile;
  }
  if (input.modules && typeof input.modules === "object") patch.modules = input.modules;
  if (input.response && typeof input.response === "object") patch.response = input.response;
  if (input.thresholds && typeof input.thresholds === "object") {
    const limits: Record<string, [number, number]> = {
      actionWindowSeconds: [2, 120],
      crossActionWindowSeconds: [5, 300],
      crossActionScore: [4, 100],
      channelDelete: [1, 30],
      channelCreate: [1, 50],
      channelUpdate: [1, 50],
      channelOverwrite: [1, 50],
      roleDelete: [1, 30],
      roleCreate: [1, 50],
      roleUpdate: [1, 50],
      banAdd: [1, 50],
      memberPrune: [1, 100000],
      kick: [1, 50],
      webhook: [1, 30],
      botAdd: [1, 10],
      guildUpdate: [1, 20],
      automodChange: [1, 20],
      raidJoins: [2, 1000],
      raidWindowSeconds: [2, 300],
      spamMessages: [2, 50],
      spamWindowSeconds: [1, 120],
      mentionLimit: [2, 100],
      linkBurst: [2, 50],
      linkWindowSeconds: [2, 300],
      minAccountAgeHours: [0, 87600]
    };
    const normalized: Record<string, number> = {};
    for (const [key, range] of Object.entries(limits)) {
      const value = Number((input.thresholds as unknown as Record<string, unknown>)[key]);
      if (!Number.isFinite(value)) continue;
      normalized[key] = Math.max(range[0], Math.min(range[1], Math.trunc(value)));
    }
    patch.thresholds = normalized as Partial<SecuritySettings["thresholds"]> as SecuritySettings["thresholds"];
  }
  for (const key of [
    "trustedUserIds",
    "trustedRoleIds",
    "allowedBotIds",
    "allowedDomains",
    "blockedDomains"
  ] as const) {
    const value = input[key];
    if (Array.isArray(value)) {
      (patch as Record<string, unknown>)[key] = value
        .map(item => String(item).trim())
        .filter(Boolean)
        .slice(0, 500);
    }
  }
  if (input.logChannelId === null || typeof input.logChannelId === "string") {
    patch.logChannelId = input.logChannelId || null;
  }
  return patch;
}

async function handleInternal(
  request: Request,
  env: Env,
  bodyText: string
): Promise<Response> {
  const url = new URL(request.url);
  const overview = url.pathname.match(/^\/internal\/guilds\/(\d+)\/overview$/);
  if (overview && request.method === "GET") {
    const guildId = overview[1]!;
    const managedServiceBots = await listManagedServiceBots(env, guildId);
    const managedBotIds = [
      ...managedServiceBots.map(item => item.botId),
      ...(env.MAIN_BOT_APPLICATION_ID?.trim() ? [env.MAIN_BOT_APPLICATION_ID.trim()] : [])
    ].filter((id, index, all) => all.indexOf(id) === index);
    const [settings, status, incidents, lockdown, guild, capabilities] = await Promise.all([
      getSecuritySettings(env, guildId),
      gatewayStatus(env),
      listIncidents(env, guildId, Number(url.searchParams.get("limit") ?? 30)),
      getLockdownSnapshot(env, guildId),
      botJson<{ id: string; name: string }>(env, `/guilds/${guildId}`).catch(() => null),
      getSecurityCapabilities(
        env,
        guildId,
        managedBotIds
      )
    ]);
    const permissions = (
      128n | 32n | 268435456n | 16n | 536870912n | 8192n |
      1099511627776n | 2n | 4n | 1024n | 2048n | 16384n
    ).toString();
    return json({
      configured: true,
      installed: Boolean(guild),
      managedServiceBots,
      mainBotApplicationIdConfigured: Boolean(env.MAIN_BOT_APPLICATION_ID?.trim()),
      capabilities,
      inviteUrl:
        `https://discord.com/oauth2/authorize?client_id=${encodeURIComponent(env.DISCORD_APPLICATION_ID)}` +
        `&permissions=${permissions}&integration_type=0&scope=bot%20applications.commands`,
      maximumInviteUrl:
        `https://discord.com/oauth2/authorize?client_id=${encodeURIComponent(env.DISCORD_APPLICATION_ID)}` +
        `&permissions=8&integration_type=0&scope=bot%20applications.commands`,
      settings,
      status,
      incidents,
      lockdown: lockdown
        ? { active: true, expiresAt: lockdown.expiresAt, reason: lockdown.reason }
        : { active: false, expiresAt: null, reason: null }
    });
  }

  const serviceBots = url.pathname.match(/^\/internal\/guilds\/(\d+)\/service-bots$/);
  if (serviceBots && request.method === "POST") {
    const body = bodyText ? JSON.parse(bodyText) as { botId?: string; kind?: string } : {};
    const botId = String(body.botId ?? "");
    if (!/^\d+$/.test(botId)) return json({ error: "invalid_bot_id" }, 400);
    await registerManagedServiceBot(
      env,
      serviceBots[1]!,
      botId,
      String(body.kind ?? "main")
    );
    return json({ ok: true }, 201);
  }

  const settingsMatch = url.pathname.match(/^\/internal\/guilds\/(\d+)\/settings$/);
  if (settingsMatch && request.method === "GET") {
    return json(await getSecuritySettings(env, settingsMatch[1]!));
  }
  if (settingsMatch && request.method === "PUT") {
    const body = bodyText ? JSON.parse(bodyText) : {};
    const saved = await saveSecuritySettings(
      env,
      settingsMatch[1]!,
      settingsPatch(body)
    );
    await invalidateGatewaySettings(env, settingsMatch[1]!);
    return json(saved);
  }

  const maintenance = url.pathname.match(
    /^\/internal\/guilds\/(\d+)\/maintenance$/
  );
  if (maintenance && request.method === "POST") {
    const body = bodyText ? JSON.parse(bodyText) as {
      actorId?: string;
      scope?: MaintenanceScope;
      seconds?: number;
    } : {};
    const actorId = String(body.actorId ?? "");
    const scope = body.scope;
    if (!/^\d+$/.test(actorId)) return json({ error: "invalid_actor" }, 400);
    if (!["dashboard_edit", "restore", "all"].includes(String(scope))) {
      return json({ error: "invalid_scope" }, 400);
    }
    return json(await createMaintenanceLease(
      env,
      maintenance[1]!,
      actorId,
      scope as MaintenanceScope,
      Number(body.seconds ?? 30)
    ), 201);
  }

  const lockdown = url.pathname.match(
    /^\/internal\/guilds\/(\d+)\/lockdown$/
  );
  if (lockdown && request.method === "POST") {
    const settings = await getSecuritySettings(env, lockdown[1]!);
    const body = bodyText ? JSON.parse(bodyText) as {
      minutes?: number;
      reason?: string;
    } : {};
    const changed = await enterLockdown(
      env,
      lockdown[1]!,
      Number(body.minutes ?? settings.response.lockdownMinutes),
      String(body.reason ?? "manual dashboard lockdown")
    );
    return json({ ok: true, changed });
  }
  if (lockdown && request.method === "DELETE") {
    return json({
      ok: true,
      changed: await exitLockdown(env, lockdown[1]!)
    });
  }

  return json({ error: "not_found" }, 404);
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/health") {
      const status = await gatewayStatus(env);
      return json({
        ok: true,
        service: "discord-security",
        gateway: {
          connected: status.connected,
          lastHeartbeatAck: status.lastHeartbeatAck,
          lastEventAt: status.lastEventAt,
          reconnectAttempts: status.reconnectAttempts
        }
      });
    }

    if (!url.pathname.startsWith("/internal/")) {
      return json({ error: "not_found" }, 404);
    }

    const bodyText = request.method === "GET" ? "" : await request.text();
    if (!(await verifyBridge(request, env, bodyText))) {
      return json({ error: "unauthorized" }, 401);
    }

    await ensureSchema(env);
    ctx.waitUntil(ensureDiscordSecurityGateway(env));
    try {
      return await handleInternal(request, env, bodyText);
    } catch (error) {
      console.error("internal security API failed", error);
      return json({
        error: "server_error",
        message: error instanceof Error ? error.message : "unknown error"
      }, 500);
    }
  },

  async scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext
  ): Promise<void> {
    await ensureSchema(env);
    ctx.waitUntil((async () => {
      await cleanExpired(env);
      await ensureDiscordSecurityGateway(env);
      await reconcileDiscordSecurityAudits(env).catch(error => {
        console.error("scheduled audit reconciliation failed", error);
      });
      for (const guildId of await listExpiredLockdowns(env)) {
        await exitLockdown(env, guildId).catch(error => {
          console.error("lockdown restore failed", guildId, error);
        });
      }
    })());
  }
} satisfies ExportedHandler<Env>;
