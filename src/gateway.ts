import type {
  AuditEntry,
  DiscordMemberAddEvent,
  DiscordMessageEvent,
  Env,
  GatewayStatus
} from "./types";
import { SecurityEngine } from "./engine";

type StoredGatewayState = GatewayStatus & {
  sequence: number | null;
  resumeUrl: string | null;
  heartbeatInterval: number | null;
  lastHeartbeatSent: number | null;
  guildIds: string[];
};

type GatewayPayload = {
  op: number;
  t?: string | null;
  s?: number | null;
  d?: unknown;
};

const STATE_KEY = "discord_security_gateway_state";
const GATEWAY_VERSION = 10;
const GUILDS = 1 << 0;
const GUILD_MEMBERS = 1 << 1;
const GUILD_MODERATION = 1 << 2;
const GUILD_INTEGRATIONS = 1 << 4;
const GUILD_WEBHOOKS = 1 << 5;
const GUILD_MESSAGES = 1 << 9;
const MESSAGE_CONTENT = 1 << 15;
const GATEWAY_INTENTS =
  GUILDS |
  GUILD_MEMBERS |
  GUILD_MODERATION |
  GUILD_INTEGRATIONS |
  GUILD_WEBHOOKS |
  GUILD_MESSAGES |
  MESSAGE_CONTENT;
const RECONNECT_CLOSE_CODE = 3001;

function emptyState(): StoredGatewayState {
  return {
    connected: false,
    sessionId: null,
    sequence: null,
    resumeUrl: null,
    heartbeatInterval: null,
    lastHeartbeatSent: null,
    lastHeartbeatAck: null,
    lastEventAt: null,
    reconnectAttempts: 0,
    botUserId: null,
    guildIds: []
  };
}

function websocketUpgradeUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol === "wss:") url.protocol = "https:";
  if (url.protocol === "ws:") url.protocol = "http:";
  url.searchParams.set("v", String(GATEWAY_VERSION));
  url.searchParams.set("encoding", "json");
  return url.toString();
}

function clearSessionOnClose(code: number): boolean {
  return code === 4007 || code === 4009;
}

function fatalClose(code: number): boolean {
  return [4004, 4010, 4011, 4012, 4013, 4014].includes(code);
}

export async function ensureDiscordSecurityGateway(env: Env): Promise<void> {
  const id = env.SECURITY_GATEWAY.idFromName("discord-security");
  const response = await env.SECURITY_GATEWAY.get(id).fetch(
    "https://security-gateway.internal/start",
    { method: "POST" }
  );
  if (!response.ok) {
    throw new Error(
      "Discord Security Gateway start failed: " +
      response.status + " " + await response.text()
    );
  }
}

export async function reconcileDiscordSecurityAudits(env: Env): Promise<void> {
  const id = env.SECURITY_GATEWAY.idFromName("discord-security");
  const response = await env.SECURITY_GATEWAY.get(id).fetch(
    "https://security-gateway.internal/reconcile",
    { method: "POST" }
  );
  if (!response.ok) {
    throw new Error(
      "Discord Security audit reconciliation failed: " +
      response.status + " " + await response.text()
    );
  }
}

export async function gatewayStatus(env: Env): Promise<GatewayStatus> {
  const id = env.SECURITY_GATEWAY.idFromName("discord-security");
  const response = await env.SECURITY_GATEWAY.get(id).fetch(
    "https://security-gateway.internal/status"
  );
  if (!response.ok) return emptyState();
  return await response.json() as GatewayStatus;
}

export class DiscordSecurityGateway {
  private socket: WebSocket | null = null;
  private plannedClose = false;
  // Protocol/control frames must never wait behind Discord REST moderation
  // calls. queue handles WebSocket state/heartbeats; eventQueue preserves
  // dispatch order for slower SecurityEngine work.
  private queue: Promise<void> = Promise.resolve();
  private eventQueue: Promise<void> = Promise.resolve();
  private readonly engine: SecurityEngine;

  constructor(
    private readonly state: DurableObjectState,
    private readonly env: Env
  ) {
    this.engine = new SecurityEngine(env);
  }

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/status" && request.method === "GET") {
      const stored = await this.loadState();
      return Response.json({
        connected: Boolean(this.socket) && stored.connected,
        sessionId: stored.sessionId,
        lastHeartbeatAck: stored.lastHeartbeatAck,
        lastEventAt: stored.lastEventAt,
        reconnectAttempts: stored.reconnectAttempts,
        botUserId: stored.botUserId
      } satisfies GatewayStatus);
    }
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    if (path === "/start") {
      if (!this.socket) await this.connect();
      return Response.json({ ok: true });
    }
    if (path === "/stop") {
      await this.stop();
      return Response.json({ ok: true });
    }
    if (path === "/reconcile") {
      const stored = await this.loadState();
      for (const guildId of stored.guildIds) {
        await this.engine.reconcileGuild(guildId).catch(error => {
          console.error("security audit reconcile failed", guildId, error);
        });
      }
      return Response.json({ ok: true, guilds: stored.guildIds.length });
    }
    if (path.startsWith("/invalidate/")) {
      this.engine.invalidateSettings(path.slice("/invalidate/".length));
      return Response.json({ ok: true });
    }
    return new Response("Not Found", { status: 404 });
  }

  async alarm(): Promise<void> {
    try {
      if (!this.socket) {
        await this.connect();
        return;
      }
      const stored = await this.loadState();
      if (!stored.heartbeatInterval) {
        await this.state.storage.setAlarm(Date.now() + 5000);
        return;
      }
      if (
        stored.lastHeartbeatSent !== null &&
        (stored.lastHeartbeatAck === null ||
          stored.lastHeartbeatAck < stored.lastHeartbeatSent)
      ) {
        await this.scheduleReconnect(false);
        return;
      }
      this.sendHeartbeat(stored);
      stored.lastHeartbeatSent = Date.now();
      await this.saveState(stored);
      await this.state.storage.setAlarm(
        Date.now() + Math.max(1000, stored.heartbeatInterval)
      );
    } catch (error) {
      console.error("security gateway alarm failed", error);
      await this.state.storage.setAlarm(Date.now() + 15_000);
    }
  }

  private async loadState(): Promise<StoredGatewayState> {
    return (await this.state.storage.get<StoredGatewayState>(STATE_KEY)) ?? emptyState();
  }

  private async saveState(value: StoredGatewayState): Promise<void> {
    await this.state.storage.put(STATE_KEY, value);
  }

  private async gatewayUrl(): Promise<string> {
    const response = await fetch("https://discord.com/api/v10/gateway/bot", {
      headers: { Authorization: `Bot ${this.env.DISCORD_BOT_TOKEN}` }
    });
    if (!response.ok) {
      throw new Error(
        "Discord gateway URL failed: " + response.status + " " + await response.text()
      );
    }
    const data = await response.json() as { url?: string };
    if (!data.url) throw new Error("Discord gateway URL missing");
    return data.url;
  }

  private async connect(): Promise<void> {
    if (this.socket) return;
    const stored = await this.loadState();
    const resumable =
      Boolean(stored.sessionId) &&
      stored.sequence !== null &&
      Boolean(stored.resumeUrl);

    let baseUrl: string;
    try {
      baseUrl = resumable ? stored.resumeUrl! : await this.gatewayUrl();
    } catch (error) {
      console.error("security gateway URL resolution failed", error);
      await this.scheduleReconnect(false);
      return;
    }

    let response: Response;
    try {
      response = await fetch(websocketUpgradeUrl(baseUrl), {
        headers: { Upgrade: "websocket" }
      });
    } catch (error) {
      console.error("security websocket upgrade failed", error);
      await this.scheduleReconnect(false);
      return;
    }

    if (!response.webSocket) {
      console.error("security websocket missing", response.status);
      await this.scheduleReconnect(false);
      return;
    }

    const socket = response.webSocket;
    socket.accept();
    this.socket = socket;
    this.plannedClose = false;

    socket.addEventListener("message", event => {
      if (this.socket !== socket) return;
      this.queue = this.queue
        .then(() => this.handleMessage(String(event.data)))
        .catch(error => console.error("security gateway event failed", error));
    });

    socket.addEventListener("close", event => {
      if (this.socket !== socket) return;
      this.socket = null;
      if (this.plannedClose) {
        this.plannedClose = false;
        return;
      }
      void this.scheduleReconnect(
        clearSessionOnClose(event.code),
        fatalClose(event.code) ? 60_000 : undefined
      );
    });

    socket.addEventListener("error", () => {
      if (this.socket !== socket) return;
      this.socket = null;
      if (!this.plannedClose) void this.scheduleReconnect(false);
    });

    await this.state.storage.setAlarm(Date.now() + 10_000);
  }

  private async stop(): Promise<void> {
    await this.state.storage.deleteAlarm();
    if (this.socket) {
      this.plannedClose = true;
      try {
        this.socket.close(1000, "security gateway stopped");
      } catch {
        // already closed
      }
      this.socket = null;
    }
    await this.state.storage.put(STATE_KEY, emptyState());
  }

  private async scheduleReconnect(
    clearSession: boolean,
    forcedDelay?: number
  ): Promise<void> {
    const stored = await this.loadState();
    stored.connected = false;
    stored.reconnectAttempts += 1;
    stored.heartbeatInterval = null;
    stored.lastHeartbeatSent = null;
    stored.lastHeartbeatAck = null;
    if (clearSession) {
      stored.sessionId = null;
      stored.sequence = null;
      stored.resumeUrl = null;
    }
    await this.saveState(stored);

    if (this.socket) {
      this.plannedClose = true;
      try {
        this.socket.close(RECONNECT_CLOSE_CODE, "reconnect");
      } catch {
        // already closed
      }
      this.socket = null;
    }
    const delay =
      forcedDelay ??
      Math.min(60_000, 1000 * 2 ** Math.min(stored.reconnectAttempts, 5));
    await this.state.storage.setAlarm(Date.now() + delay);
  }

  private async handleMessage(raw: string): Promise<void> {
    let payload: GatewayPayload;
    try {
      payload = JSON.parse(raw) as GatewayPayload;
    } catch {
      return;
    }

    const stored = await this.loadState();
    if (payload.s !== undefined && payload.s !== null) {
      stored.sequence = payload.s;
    }

    switch (payload.op) {
      case 10: {
        const hello = payload.d as { heartbeat_interval?: number };
        if (!hello.heartbeat_interval) {
          await this.scheduleReconnect(false);
          return;
        }
        stored.heartbeatInterval = hello.heartbeat_interval;
        stored.lastHeartbeatAck = Date.now();
        stored.lastHeartbeatSent = null;
        await this.saveState(stored);
        await this.identifyOrResume(stored);
        await this.state.storage.setAlarm(
          Date.now() + Math.max(1000, Math.floor(hello.heartbeat_interval * Math.random()))
        );
        return;
      }
      case 11:
        stored.lastHeartbeatAck = Date.now();
        await this.saveState(stored);
        return;
      case 1:
        this.sendHeartbeat(stored);
        return;
      case 7:
        await this.scheduleReconnect(false, 1000);
        return;
      case 9:
        await this.scheduleReconnect(payload.d !== true, 1000 + Math.random() * 4000);
        return;
      case 0:
        stored.lastEventAt = Date.now();
        await this.saveState(stored);
        await this.handleDispatch(payload, stored);
        return;
    }
  }

  private async identifyOrResume(stored: StoredGatewayState): Promise<void> {
    if (!this.socket) return;
    if (stored.sessionId && stored.sequence !== null && stored.resumeUrl) {
      this.socket.send(JSON.stringify({
        op: 6,
        d: {
          token: this.env.DISCORD_BOT_TOKEN,
          session_id: stored.sessionId,
          seq: stored.sequence
        }
      }));
      return;
    }
    this.socket.send(JSON.stringify({
      op: 2,
      d: {
        token: this.env.DISCORD_BOT_TOKEN,
        intents: GATEWAY_INTENTS,
        properties: {
          os: "cloudflare",
          browser: "discord-security",
          device: "discord-security"
        }
      }
    }));
  }

  private sendHeartbeat(stored: StoredGatewayState): void {
    if (!this.socket) return;
    this.socket.send(JSON.stringify({ op: 1, d: stored.sequence }));
  }

  private enqueueSecurityEvent(
    label: string,
    work: () => Promise<void>
  ): void {
    this.eventQueue = this.eventQueue
      .then(work)
      .catch(error => console.error(label, error));
  }

  private async handleDispatch(
    payload: GatewayPayload,
    stored: StoredGatewayState
  ): Promise<void> {
    if (payload.t === "READY") {
      const ready = payload.d as {
        session_id?: string;
        resume_gateway_url?: string;
        user?: { id?: string };
        guilds?: Array<{ id?: string }>;
      };
      stored.connected = true;
      stored.sessionId = ready.session_id ?? null;
      stored.resumeUrl = ready.resume_gateway_url ?? stored.resumeUrl;
      stored.reconnectAttempts = 0;
      stored.botUserId = ready.user?.id ?? null;
      stored.guildIds = (ready.guilds ?? [])
        .map(guild => String(guild.id ?? ""))
        .filter(Boolean);
      await this.saveState(stored);
      for (const guildId of stored.guildIds) {
        this.enqueueSecurityEvent(
          "initial audit reconcile failed " + guildId,
          () => this.engine.reconcileGuild(guildId)
        );
      }
      return;
    }
    if (payload.t === "RESUMED") {
      stored.connected = true;
      stored.reconnectAttempts = 0;
      await this.saveState(stored);
      return;
    }
    if (payload.t === "GUILD_CREATE") {
      const guildId = String((payload.d as { id?: string })?.id ?? "");
      if (guildId && !stored.guildIds.includes(guildId)) {
        stored.guildIds.push(guildId);
        await this.saveState(stored);
        this.enqueueSecurityEvent(
          "guild create audit reconcile failed " + guildId,
          () => this.engine.reconcileGuild(guildId)
        );
      }
      return;
    }
    if (payload.t === "GUILD_DELETE") {
      const guildId = String((payload.d as { id?: string })?.id ?? "");
      if (guildId) {
        stored.guildIds = stored.guildIds.filter(id => id !== guildId);
        await this.saveState(stored);
      }
      return;
    }
    if (payload.t === "GUILD_AUDIT_LOG_ENTRY_CREATE") {
      const entry = payload.d as AuditEntry;
      this.enqueueSecurityEvent(
        "security audit event failed",
        () => this.engine.handleAudit(entry)
      );
      return;
    }
    if (payload.t === "GUILD_MEMBER_ADD") {
      const event = payload.d as DiscordMemberAddEvent;
      this.enqueueSecurityEvent(
        "security member event failed",
        () => this.engine.handleJoin(event)
      );
      return;
    }
    if (payload.t === "MESSAGE_CREATE") {
      const event = payload.d as DiscordMessageEvent;
      this.enqueueSecurityEvent(
        "security message event failed",
        () => this.engine.handleMessage(event)
      );
    }
  }
}
