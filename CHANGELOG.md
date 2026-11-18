# Changelog

Release notes for this project. Format follows [Keep a Changelog](https://keepachangelog.com/), versions follow [SemVer](https://semver.org/).

## v2.0.3

- **Custom LLM session header**: each LLM profile can set one HTTP header whose value is automatically the current conversation session id — fits gateways like opencode that do prompt caching / sticky routing per session.
- **Global egress proxy**: all agent target traffic can exit through a single egress proxy (http/https/socks5) to hide the source IP or bounce through a jump host; includes an "availability test" (echoes the egress IP through the proxy).
- **Per-task egress selection**: when creating a task you can choose whether it uses the global proxy or connects directly.
- **Enrich-on-confirm**: manually confirming a finding automatically enriches it into structured data, so confirmed findings are deliverable.
- **Report management**: new reports list only confirmed findings by default (with status / CVSS); report bodies reuse enriched data.
- **Auto-filled evidence captions**: evidence screenshot captions are generated from reproduction-step text and are editable.
- **Finding detail polish**: status dropdown, section titles, one-click copy.
- **Traffic task-filter fix**: task filtering now also applies the task activity time window, so repeated tests against the same target no longer mix traffic.
- System settings page switched to a two-column responsive layout.

## v2.0.2

- **One-click update**: check for and install new GitHub releases from the system settings page (SHA256 verification / atomic swap / automatic rollback on failure); data is unaffected.
- Release archives now bundle the `start.sh` supervisor script and a systemd template.

## v2.0.1

- Reproduction steps automatically link to the real captured traffic when saved.

## v2.0.0

- Evidence-driven delivery: reproduction captured in place, findings laid out as kill-chain steps, each step linked to its real traffic packet; human-grade trilingual reports.
