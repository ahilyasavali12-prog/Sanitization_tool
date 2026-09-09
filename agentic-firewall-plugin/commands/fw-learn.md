---
description: Add an attack prompt to the firewall's known-attack DB
argument-hint: <attack text>
---

Send this exact HTTP request (replace the JSON body with the user's arguments verbatim):

curl -s -X POST http://127.0.0.1:8100/learn -H "Content-Type: application/json" -d '{"text": "$ARGUMENTS"}'

Then report the result to the user.