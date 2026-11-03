# Malware reputation list

`GET /v1/reputation/list` serves this list, signed, to the SDK's
`malware_reputation` detector (see `src/reputation/reputationList.ts`).

1. Copy `list.example.json` to a path outside git and point
   `REPUTATION_LIST_PATH` at it.
2. Fill `entries` from a threat-intelligence source you trust:
   `{ "package": "com.example.bad", "category": "banking_trojan", "severity": "critical" }`.
   Only package names you have evidence for — a wrong entry flags a clean app.
3. Raise `version` on every change. Devices ignore a list older than the one
   they already have.
4. `npm run reputation:keygen` once; put `REPUTATION_SIGNING_KEY` in `.env`.

An empty list makes the detector report UNKNOWN ("Reputation list is empty"),
never SECURE.
