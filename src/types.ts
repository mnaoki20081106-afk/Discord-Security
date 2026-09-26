export type SecurityProfile = "balanced" | "strict" | "paranoid";
export type EnforcementMode = "audit" | "enforce";

export type SecurityModules = {
  antiNuke: boolean;
  antiRaid: boolean;
  antiSpam: boolean;
  antiPhishing: boolean;
  dangerousAttachments: boolean;
  botGuard: boolean;
  webhookGuard: boolean;
  roleGuard: boolean;
  permissionGuard: boolean;
  automodGuard: boolean;
  guildGuard: boolean;
  memberGuard: boolean;
};

export type SecurityThresholds = {
  actionWindowSeconds: number;
  crossActionWindowSeconds: number;
  crossActionScore: number;
  channelDelete: number;
  channelCreate: number;
  channelUpdate: number;
  channelOverwrite: number;
  roleDelete: number;
  roleCreate: number;
  roleUpdate: number;
  banAdd: number;
  memberPrune: number;
  kick: number;
  webhook: number;
  botAdd: number;
  guildUpdate: number;
  automodChange: number;
  raidJoins: number;
  raidWindowSeconds: number;
  spamMessages: number;
  spamWindowSeconds: number;
  mentionLimit: number;
  linkBurst: number;
  linkWindowSeconds: number;
  severeContentUsers: number;
  severeContentWindowSeconds: number;
  minAccountAgeHours: number;
};

export type SecuritySafety = {
  enforceExplicitContentFilter: boolean;
  minimumVerificationLevel: number;
};

export type SecurityResponse = {
  stripDangerousRoles: boolean;
  kickMaliciousBots: boolean;
  timeoutMinutes: number;
  autoLockdown: boolean;
  lockdownMinutes: number;
  deleteUnsafeMessages: boolean;
  quarantineRaidJoins: boolean;
};

export type SecuritySettings = {
  enabled: boolean;
  mode: EnforcementMode;
  profile: SecurityProfile;
  modules: SecurityModules;
  thresholds: SecurityThresholds;
  response: SecurityResponse;
  safety: SecuritySafety;
  logChannelId: string | null;
  trustedUserIds: string[];
  trustedRoleIds: string[];
  allowedBotIds: string[];
  allowedDomains: string[];
  blockedDomains: string[];
};

export type SecurityIncident = {
  id: string;
  guildId: string;
  actorId: string | null;
  kind: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  summary: string;
  data: Record<string, unknown>;
  createdAt: number;
};

export type MaintenanceScope = "dashboard_edit" | "restore";

export interface Env {
  DB: D1Database;
  SECURITY_GATEWAY: DurableObjectNamespace;
  DISCORD_BOT_TOKEN: string;
  DISCORD_APPLICATION_ID: string;
  MAIN_BOT_APPLICATION_ID?: string;
  SECURITY_BRIDGE_SECRET: string;
}

export type GuildSafetyStatus = {
  explicitContentFilter: number;
  verificationLevel: number;
  mfaLevel: number;
  raidAlertsEnabled: boolean;
  safetyAlertsChannelConfigured: boolean;
  baselineReady: boolean;
};

export type SecurityCapabilities = {
  administrator: boolean;
  requiredReady: boolean;
  maximumProtection: boolean;
  roleAboveManagedBots: boolean | null;
  roleAboveDangerousRoles: boolean | null;
  dangerousRolesNotBelow: Array<{
    id: string;
    name: string;
    position: number;
  }>;
  highestRoleName: string | null;
  highestRolePosition: number | null;
  missingPermissions: string[];
};

export type GatewayStatus = {
  connected: boolean;
  sessionId: string | null;
  lastHeartbeatAck: number | null;
  lastEventAt: number | null;
  reconnectAttempts: number;
  botUserId: string | null;
};

export type AuditLogChange = {
  key?: string;
  old_value?: unknown;
  new_value?: unknown;
};

export type AuditEntry = {
  id: string;
  guild_id: string;
  action_type: number;
  user_id?: string | null;
  target_id?: string | null;
  changes?: AuditLogChange[];
  options?: Record<string, unknown>;
  reason?: string | null;
};

export type DiscordMessageEvent = {
  id: string;
  guild_id?: string;
  channel_id: string;
  author: {
    id: string;
    bot?: boolean;
    username?: string;
  };
  member?: {
    roles?: string[];
  };
  content?: string;
  mentions?: Array<{ id: string }>;
  mention_roles?: string[];
  attachments?: Array<{
    id: string;
    filename?: string;
    content_type?: string | null;
    size?: number;
    url?: string;
  }>;
};

export type DiscordMemberAddEvent = {
  guild_id: string;
  user: {
    id: string;
    bot?: boolean;
    username?: string;
  };
  roles?: string[];
};
