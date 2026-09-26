# Attributions and design references

This project is independently implemented. The following open-source projects were reviewed for defensive design ideas:

- Solzte/discord-guard-bot — MIT
  - Audit-log-entry-driven routing
  - Cache-first configuration
  - Modular guard separation
  - Explicit sanction outcomes
- korqedev/Public-Anti-Nuke-Discord-Bot — MIT
  - Cross-action risk scoring
  - Quarantine/lockdown concepts
  - Dangerous-permission detection
- Jonathan-p-z/Bastion — AGPL-3.0
  - Architectural reference only; no Bastion source code was copied.
  - Risk/trust scoring and staged lockdown concepts informed the high-level design.

The original projects retain their respective copyrights and licenses.
