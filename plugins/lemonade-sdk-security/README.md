# Lemonade SDK Security Plugin

This folder is the plugin boundary for exposing Lemonade Security to a
Lemonade SDK host.

The app owns:

- policy checks
- event-log auditing
- AIBOM generation aligned to the forked OWASP AIBOM generator
- `security.*` event output

The plugin should stay thin:

- call local `lemonade_security` APIs
- present findings in the SDK host
- never mutate another department's log
- never require cloud access
- require owner approval before export or sharing

No plugin runtime is implemented yet. This placeholder pins the boundary
so later work does not bury security behavior inside another department.
