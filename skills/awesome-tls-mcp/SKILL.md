---
name: awesome-tls-mcp
description: Drive the Awesome TLS Burp Suite extension through its local MCP endpoint — read settings, capture a real browser ClientHello as hex, and propose it as the global or a per-domain TLS fingerprint. Use when asked to inspect or change Awesome TLS settings, spoof or dump a TLS fingerprint (JA3/JA4/ClientHello) in Burp, or whenever awesome_tls.settings.* tools are available.
---

# Awesome TLS over MCP

Companion skill for the [Awesome TLS](https://github.com/Robin528919/burp-awesome-tls-plus) Burp
Suite extension, which spoofs browser TLS fingerprints on Burp's outgoing traffic. The extension can
expose a local MCP endpoint; this file is what tells you how to drive it correctly.

**Prerequisites** — if the `awesome_tls.settings.*` tools are not visible: the user must open
**Awesome TLS → AI Control** in Burp, tick the acknowledgement (remembered after the first time) and
press **Enable** (off by default, and never comes back on its own after a Burp restart), then
register the endpoint with their client.
The tab's *Connect a client* section copies the exact command.

Exactly two tools exist, on `http://127.0.0.1:8885/mcp` (port configurable, loopback only, **no
authentication** — anything running as that user can read the settings through it):

| Tool | Effect |
| --- | --- |
| `awesome_tls.settings.inspect` | Read committed settings, valid domain rules, the fingerprint catalog, listener state, pending proposal, and the effective config for given hosts. Read-only; never resolves DNS or touches a target. |
| `awesome_tls.settings.propose` | Validate and record **one** change for the user to review. Writes nothing. |

**There is no apply tool and there never will be.** Approve / reject / revert happen only in the
Burp UI. After a successful `propose`, stop and tell the user to open the AI Control tab — do not
poll for approval in a loop.

## 1. Always inspect first

```json
{"schemaVersion":"awesome_tls.settings.v1",
 "sections":["settings","rules","fingerprints","runtime","proposal"],
 "hosts":["example.com"]}
```

- Both keys are optional. Omitting `sections` returns everything except `effectiveConfig`, which is
  added automatically when `hosts` is present. `hosts` are bare hostnames, max 20.
- The response carries `revision` (`sha256:<64 hex>`) — `propose` requires it verbatim.
- `dirty: true` means the user has unsaved edits open in the UI; a proposal will be refused
  (`DIRTY_UI`) until they save or discard. Say so instead of retrying.
- Long values (a full hex ClientHello easily qualifies) come back as
  `{"kind":"chunk_reference", …, "cursor":"…"}`. Call `inspect` again with **only**
  `{"schemaVersion":…, "cursor":"…"}` to fetch the rest. Never treat a chunk reference as a value.

## 2. Pick a fingerprint

Two mutually exclusive forms, and precedence is fixed in the extension's Go core:

```
intercepted ClientHello  >  hexClientHello  >  named fingerprint profile
```

- **Named profile** — one of the ~80 strings in the `fingerprints` section (`chrome_146`,
  `firefox_148`, `safari_ios_26_0`, `okhttp4_android_13`, `default`, …). Never invent one; a bare
  browser name like `"chrome"` is not a valid value.
- **Hex ClientHello** — a raw captured record, see §4. Wins over any fingerprint in the same scope.
- Setting one **clears the other** in that scope: a rule that sets only `fingerprint` suppresses the
  global hex it would otherwise inherit. That is deliberate, not a bug.
- `default` in the fingerprint list is a real profile, *not* "inherit". Only an absent/`null` rule
  field inherits from the global settings.
- Rule matching: exact host beats wildcard, longer wildcard suffix beats shorter. Row order is
  irrelevant. Two rules claiming the same pattern disable **both**, rather than one winning.

## 3. Propose

```json
{"schemaVersion":"awesome_tls.settings.v1",
 "expectedRevision":"sha256:…",
 "requestId":"capture-chrome-for-example-com-1",
 "summary":"Replay the captured Chrome ClientHello for *.example.com",
 "acknowledgements":["RULE_HEX_OVERRIDES_FINGERPRINT"],
 "patch":{"domainRules":{"upsert":[
   {"hostPattern":"*.example.com","hexClientHello":"1603010200010001fc0303…"}]}}}
```

- `expectedRevision` is compare-and-set. Stale → `REVISION_CONFLICT`: re-inspect, rebuild, retry once.
- `requestId` is the idempotency key (`[A-Za-z0-9._:-]+`). Reusing it with *different* arguments is
  `REQUEST_ID_CONFLICT`; reusing it identically replays the original answer. Generate a fresh one per
  distinct intent.
- `patch` may carry `settings` (global) and/or `domainRules` (`upsert` / `remove`), at least one
  property. Unknown fields are refused, not ignored. An explicit `null` clears a clearable field.
- **Acknowledgements are mandatory when they apply** — the server refuses with
  `missing_acknowledgement` rather than guessing which half of the pair you meant:

  | Ack | Required when |
  | --- | --- |
  | `GLOBAL_HEX_OVERRIDES_FINGERPRINT` | the patch sets `settings.hexClientHello` to a non-empty value |
  | `RULE_HEX_OVERRIDES_FINGERPRINT` | an upserted rule ends up with a non-empty `hexClientHello` |
  | `RULE_FINGERPRINT_SUPPRESSES_INHERITED_HEX` | a rule's fingerprint suppresses the inherited global hex |

- Settings fields: `spoofProxyAddress`, `interceptProxyAddress`, `burpProxyAddress`, `fingerprint`,
  `hexClientHello`, `useInterceptedFingerprint`, `httpTimeout` (1–3600 s), `externalProxyUrl`.
  Rule fields: `hostPattern` (`example.com` or `*.example.com`), `enabled`, `fingerprint`,
  `hexClientHello`, `externalProxyUrl`, `httpTimeout`.
- Only one proposal exists at a time (`PROPOSAL_PENDING`). Ask the user to apply or reject the
  current one; you cannot clear it yourself.

## 4. Dump a real ClientHello to hex

The extension **cannot hand you a captured fingerprint** — the intercept proxy keeps its capture
inside the Go server and it is not readable over MCP. To get hex you can store in a config, capture
it yourself.

**Format the extension accepts**: the complete TLS record — 5-byte record header **included** — as
lowercase hex, no `0x`, no colons, no whitespace. It starts `1603` and nothing else does.

```bash
tshark -D                       # pick the interface the traffic actually leaves on

# first ClientHello addressed to a given SNI, as one hex string
tshark -i en0 -Y 'tls.handshake.type == 1 && tls.handshake.extensions_server_name == "example.com"' \
       -T fields -e tcp.payload -c 1 | tr -d ':\n' | tr 'A-F' 'a-f'
```

Always verify before proposing — a truncated capture is still valid hex and fails silently later:

```bash
python3 -c 'import sys;b=bytes.fromhex("".join(sys.argv[1].split()).replace(":","").lower());assert b[0]==0x16 and b[5]==0x01,"not a ClientHello record";assert int.from_bytes(b[3:5],"big")==len(b)-5,"truncated or multi-segment";print(f"OK {len(b)} bytes")' <hex>
```

`truncated or multi-segment` means the ClientHello spanned several TCP segments — common once ECH or
a large session ticket is present. Fall back to Wireshark: select the reassembled ClientHello record
→ right-click **Copy → …as a Hex Stream**. Any pcap you already have works equally well; the only
thing that matters is that the bytes are one whole ClientHello record.

## 5. Live capture instead of hex (global only)

`settings.useInterceptedFingerprint: true` plus `interceptProxyAddress` makes the extension replay
whatever ClientHello the last client sent through that listener. It is **global and beats every
domain rule** — if per-domain rules look dead, check this flag first. It produces nothing you can
copy, so use §4 whenever the fingerprint needs to be stored, shared, or scoped to one host.

## 6. Error codes worth handling

| Code | Meaning / next move |
| --- | --- |
| `REVISION_CONFLICT` | Settings moved under you. Re-inspect, rebuild the patch, retry once. |
| `DIRTY_UI` | Unsaved edits in Burp. Ask the user to save or discard. |
| `PROPOSAL_PENDING` | A proposal is already waiting. Ask the user to apply or reject it. |
| `VALIDATION_FAILED` | Bad field, invalid fingerprint name, or a missing acknowledgement. Read `details`. |
| `AMBIGUOUS_FINGERPRINT_HEX` | The patch leaves it unclear which of the pair should win. Set both explicitly. |
| `CONTROL_DISABLED` | AI Control is off, or Burp restarted. Ask the user to re-enable it. |
| `RULE_FILE_INVALID` | `rules.json` is unparseable; nothing was touched. Do not attempt a repair patch. |
| `CURSOR_STALE` | Settings changed mid-pagination. Start the inspect over. |

## 7. Raw HTTP (debugging only)

A registered MCP client handles this for you. Curling by hand, every one of these is enforced
separately, and each has its own refusal — a missing one is never ignored:

| Header | Value | If wrong |
| --- | --- | --- |
| `Content-Type` | `application/json` | 415 |
| `Accept` | must contain **both** `application/json` and `text/event-stream` | 406 |
| `MCP-Protocol-Version` | `2026-07-28`, exactly | 400 |
| `Mcp-Method` | the JSON-RPC `method`, verbatim (`tools/list`, `tools/call`) | 400, `-32020` |
| `Mcp-Name` | on `tools/call`, the tool name — must equal `params.name` | 400, `-32020` |
| `Origin` | must be **absent**; the value is never even compared | 403 |

`Host` must be `127.0.0.1:<port>`.
