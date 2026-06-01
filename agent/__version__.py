"""Single source of truth for the Ares Docker Agent version.

Consumed by:
  - agent.config.Settings.agent_version (reported to the platform at
    registration and in every heartbeat),
  - the container entrypoint banner (scripts/entrypoint.sh),
  - the updater's anti-downgrade check (agent.updater).

Keep this in lockstep with the platform's LATEST_AGENT_VERSION
(services/hunt-agent-manager/main.py) so a freshly-built current agent reads
as "up to date" in the dashboard.
"""

__version__ = "2.5.3"
"""Current agent build version (semver, no leading 'v')."""
