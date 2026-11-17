# Cyber Tracker

A live 3D globe of newly reported cyberattacks.

- `index.html` is the whole site: globe, feed, filters and stats. No build step.
- `data/incidents.json` holds the incidents. The page re-reads it every minute.
- `scripts/collect.py` finds new incidents (leak sites via Ransomware.live, security and news RSS feeds). `.github/workflows/update.yml` runs it every 15 minutes and commits the result.

## Incident format

`data/incidents.json` is `{"lastRun": <epoch ms>, "incidents": [...]}`. Each incident:

| field | meaning |
|---|---|
| `id` | `YYYY-MM-DD-short-slug`, unique |
| `title`, `target`, `summary` | English headline, organisation name, one or two sentences |
| `type` | `ransomware`, `breach`, `supply`, `intrusion`, `ddos` or `other` |
| `status` | `confirmed`, `ongoing` or `claimed` (attacker's claim, not verified) |
| `country`, `place`, `lat`, `lon` | where the affected organisation is based |
| `ts` | epoch ms when it was reported; `timeKnown: true` if the time of day is known |
| `source`, `url` | where it was reported |
| `added` | epoch ms when it was added here (drives the NEW badge) |
