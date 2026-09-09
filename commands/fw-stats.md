---
description: Show firewall statistics and recent audit entries
---

Fetch both endpoints and present the results as a short table:

1. curl -s http://127.0.0.1:8100/stats
2. curl -s "http://127.0.0.1:8100/audit?n=15"