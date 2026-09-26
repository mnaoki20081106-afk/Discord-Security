# Discord-Security

Independent defensive Discord security service for the existing **Discord-Bot** project.

The important design decision is intentional:

- **Main Bot** owns normal server management, verification, vending, tickets and backup/restore.
- **Security Bot** owns containment and threat detection.
- The **only dashboard remains the Main Bot dashboard**.
- Security has its **own Discord token, Worker, D1 database and Gateway connection**, so a Main Bot failure does not automatically disable server protection.

## Protection model

### Real-time Gateway protections

The bot consumes Discord Gateway events directly for the fast path. A scheduled Audit Log reconciliation pass also runs as a safety net so a brief Gateway disconnect does not create a silent protection gap.

- `GUILD_AUDIT_LOG_ENTRY_CREATE`
- `GUILD_MEMBER_ADD`
- `MESSAGE_CREATE`

Tracked destructive activity includes:

- Channel create/update/delete
- Channel permission-overwrite create/update/delete
- Role create/update/delete
- Dangerous permission escalation
- Dangerous role assignment
- Mass kick / mass ban / member prune
- Unauthorized bot additions
- Unauthorized webhook creation/update/delete
- Guild-level destructive changes
- AutoMod rule tampering
- Integration changes

### Cross-action risk engine

The system does not only count one action type. A mixed sequence such as:

`role delete -> channel delete -> webhook create`

is scored across a rolling window. This catches attacks deliberately kept under individual per-action limits.

### Containment

Depending on settings:

- Strip dangerous roles from the actor
- Timeout suspicious human actors
- Kick malicious bot actors
- Immediately kick unapproved newly-added bots
- Remove newly-created unauthorized webhooks
- Roll back dangerous role permission escalation
- Remove dangerous roles that were assigned without authorization
- Enter a server-wide emergency lockdown

### Emergency lockdown

Before applying a lockdown, the bot snapshots the current channel/category permission overwrites in its **own D1**. It hardens role and member-specific overwrites too, preventing an explicit Allow from bypassing an `@everyone` deny. Synced category children are left synced where possible.

During lockdown it denies:

- Send Messages
- Add Reactions
- Connect / Speak
- Create Public/Private Threads
- Send Messages in Threads

When the lockdown expires (or an administrator unlocks it from the Main dashboard), the original overwrites are restored.

This is **incident containment**, not the server backup system. Full backup/restore stays in Main Bot.

### Raid and content protection

- Join-rate raid detection
- Temporary quarantine/timeouts for raid arrivals
- Account-age signal during raids
- Sliding-window spam detection
- Mass mention detection
- Phishing URL risk heuristics
- Per-guild allow/block domains
- Dangerous executable/script attachment blocking

Security incidents intentionally store **metadata, not message bodies or attachment files**.

For illegal sexual content or other severe platform-safety violations, this project does not attempt to build a private CSAM image collection or copy suspect media into logs. Discord's own safety/reporting systems remain essential; the bot's role is rapid containment and moderation support.

## Main Bot bridge

The browser never receives a Security Bot secret.

```text
Browser
  |
  v
Main Worker (normal dashboard authentication)
  |
  | HMAC-SHA256 signed internal request
  v
Discord-Security Worker
  |
  +-- Security D1
  +-- Durable Object Discord Gateway
```

Requests are signed with `SECURITY_BRIDGE_SECRET` and expire after 60 seconds.

### Maintenance leases

The Main Bot is intentionally **not permanently whitelisted**. Its bot ID is registered separately as a managed service bot so re-adding Main does not trigger Bot Guard, while destructive actions performed by Main are still monitored.

When Main legitimately performs a destructive operation, Main requests a short-lived signed maintenance lease. Backup restore renews a short `restore` lease while a restore job is actually running.

This preserves the important property that a compromised Main Bot can still be contained by Security Bot outside an authorized maintenance window.

## Required Cloudflare secrets

Set these on the **Discord-Security Worker**:

```text
DISCORD_BOT_TOKEN
DISCORD_APPLICATION_ID
SECURITY_BRIDGE_SECRET
```

Use a random `SECURITY_BRIDGE_SECRET` of at least 32 bytes/characters and set the **same value** on the Main Worker.

The Main Worker also needs:

```text
SECURITY_API_BASE_URL=https://discord-security.<account>.workers.dev
SECURITY_BRIDGE_SECRET=<same secret>
```

## Discord Developer Portal

Create a separate Discord application for Security Bot.

Enable privileged intents:

- Server Members Intent
- Message Content Intent

Recommended server permissions (hardened minimum):

- View Audit Log
- View Channels
- Manage Channels
- Manage Roles
- Manage Webhooks
- Manage Messages
- Moderate Members
- Kick Members
- Ban Members

Administrator is not required for the hardened-minimum mode. For **maximum protection**, Administrator is supported and the dashboard reports it as Maximum Protection because it prevents channel permission overwrites from locking the Security Bot out. This increases the impact of a leaked Security Bot token, so the Security token must remain isolated in the Security Worker secret store.

**Role hierarchy matters:** the Security Bot role must be above the Main Bot and above every role it may need to strip or contain. The dashboard now diagnoses both permission readiness and Main/Security role ordering.

## Deployment

Cloudflare Worker configuration is in `wrangler.jsonc`.

```bash
npm install
npm run typecheck
npm test
npx wrangler deploy
```

The Worker uses:

- Cloudflare Workers
- D1
- Durable Objects
- a one-minute watchdog/recovery sweep

Detection is Gateway-driven in real time, with Audit Log reconciliation as a second path for events that may have occurred during reconnects.

## Dashboard

Do not create a second dashboard. The existing `Discord-Bot` dashboard receives a new **セキュリティ** tab and proxies authenticated settings/status requests to this service.

## Open-source references

See [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

The MIT projects were used as design references. Bastion is AGPL-3.0 and was reviewed only at an architectural level; its source was not copied into this MIT project.

## Security limitations

No Discord bot can provide an absolute guarantee. Discord role hierarchy, API availability, gateway delivery, rate limits, compromised server ownership, and platform-level enforcement remain outside this bot's control.

The goal is layered prevention, fast containment, independent failure domains, and safe recovery—not a false claim of perfect protection.
