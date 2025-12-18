# RSC Parser for Burp Suite

Parses React Server Component (RSC) responses to extract security-relevant data.

RSC is a React feature using the "Flight" wire protocol. Mostly seen in Next.js, but also used by Waku, Shopify Hydrogen, and RedwoodJS.

## Install

1. Burp > Extender > Options > set Python Environment to Jython
2. Extender > Extensions > Add > select `nextjs-rsc-parser.py`

## What It Does

RSC responses (`text/x-component`) contain serialized React trees with embedded data. This extension parses them and surfaces:

- **Route parameters** (IDOR targets)
- **Sensitive values** (JWTs, API keys, tokens - detected by pattern, not keyword)
- **Entity arrays** (database records)
- **Text content** (rendered strings)
- **Server actions** (RPC endpoints)

## Usage

When viewing an RSC response, click the **RSC Parsed** tab. Four sub-tabs:

| Tab | Purpose |
|-----|---------|
| Parsed | Human-readable extraction |
| Tree | Hierarchical view |
| JSON | Raw parsed data |
| Security | Findings summary |

Right-click context menu:
- Extract Chunk URLs
- Analyze Components (Security)
- Export Parsed RSC

## Example Output

```
============================================================
NEXT.JS RSC PARSED RESPONSE
============================================================

[BUILD ID]
  abc123def456

[ROUTE STRUCTURE]
  /users/:userId/settings

[ROUTE PARAMETERS]
  userId = 8f14e45f-ceea-467f-8a53

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[INTERESTING DATA] (2 items)
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

  Path: flight_manifest
  WHY: value_pattern:JWT                        <-- detected by format, not key name
  Keys: JWT
    {
        "JWT": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw..."
    }

  Path: line_5
  WHY: value_pattern:email
  Keys: email
    {
        "email": "user@example.com"
    }

[ENTITY ARRAYS] (1 found)
  (Arrays of records - likely database entities)

  Path: line_12.users
  Count: 25 records
  Keys: id, name, email, role, createdAt
  Sample:
    {
        "id": "usr_abc123",
        "name": "John Doe",
        "email": "john@example.com",
        "role": "admin"
    }

[SERVER ACTIONS] (2 found)
  (These are server-side functions callable from client)
  $Fa - line_3
  $Fb - line_7

[TEXT CONTENT] (8 unique strings)
  "Welcome back, John"
  "https://staging.internal.example.com/api"
  "Dashboard"
  "Settings"
  ...

[METADATA]
  title: My App
  description: ...

[COMPONENTS] (5 found)
  - ClientPageRoot
  - UserSettings
  - AdminPanel
  ...
```

## Detection Patterns

Sensitive values detected by **format**, not key name:

| Pattern | Example |
|---------|---------|
| JWT | `eyJhbG...` |
| Stripe | `sk_live_`, `pk_live_` |
| GitHub | `ghp_`, `gho_` |
| AWS | `AKIA...` |
| Google | `ya29.`, `AIza...` |
| Slack | `xoxb-`, `xoxp-` |

This catches tokens even when buried in query strings or oddly-named fields.

## Tips

1. **Route params** → test for IDOR by modifying IDs
2. **Server actions** → fuzz `$F` references for auth bypass
3. **Entity arrays** → check if you're seeing other users' data
4. **URLs in text** → staging/internal endpoints
