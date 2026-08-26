# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Burp Suite extension ("Awesome TLS") that hijacks Burp's HTTP/TLS stack so outgoing
requests carry a spoofed browser TLS fingerprint (JA3) instead of Burp's Java stack
fingerprint. It is a fork of `sleeyax/burp-awesome-tls`.

The repository is **`Robin528919/burp-awesome-tls-plus`**. Four related names differ on purpose,
so do not substitute one for another: the repo (`burp-awesome-tls-plus`), the product shown in
Burp (*Awesome TLS*), the upstream project (`sleeyax/burp-awesome-tls`, no `-plus`), and the
release assets (`Burp-Awesome-TLS-Plus-<platform>.jar`, renamed from the Gradle output by
`build.sh`).

Two languages, one artifact: a **Java** Burp extension that talks over **JNA** to a
**Go** shared library doing the actual TLS work.

## Build

The Go library must be built first — the compiled binary is `.gitignore`d, so a fresh
clone cannot produce a working jar from Gradle alone.

```sh
# 1. Build the Go c-shared library into the JNA resource dir for your platform
cd src-go/server
go build -o ../../src/main/resources/{OS}-{ARCH}/{PREFIX}server.{EXT} -buildmode=c-shared ./cmd/main.go

# 2. Build the jar (output: ./build/libs/burp-awesome-tls-plus.jar — rootProject.name in settings.gradle)
./gradlew buildJar
```

`{OS}-{ARCH}` must match JNA's platform naming, and macOS needs a `lib` prefix — see
`ServerLibrary.java:8` for the runtime lookup and `build.sh` for the full table:

| Platform | Resource dir | File |
|---|---|---|
| macOS x64 / arm64 | `darwin-x86-64` / `darwin-aarch64` | `libserver.dylib` |
| Linux x86 / x64 / arm / arm64 | `linux-x86` / `linux-x86-64` / `linux-arm` / `linux-aarch64` | `server.so` |
| Windows x86 / x64 | `win32-x86` / `win32-x86-64` | `server.dll` |

`./build.sh` produces the per-platform *and* fat jars, but expects prebuilt xgo output in
`src-go/server/build/` — it does not compile Go itself. CI (`.github/workflows/release.yaml`)
runs xgo first, then `build.sh`.

The Go library also runs standalone for debugging: `go run ./cmd/main.go -spoof 127.0.0.1:8887`.

## Tests

There is still no test framework. Checks are executable `main` methods, listed in `build.gradle`
and run together:

```sh
./gradlew checkAll
```

That runs three groups:

- **`selfCheck`** — sixteen `main`-method self-checks. Each lives in the class it exercises and is
  documented there. The load-bearing ones are `burp.control.SettingsControlCheck` (crash and
  fault injection across the two-store commit), `burp.control.AiSettingsServiceCheck` (what an AI
  may and may not do), and `burp.control.McpServerCheck` (the full HTTP/JSON-RPC contract, against
  a real listener).
- **`noNetworkCheck`** — installs a counting `InetAddressResolverProvider` and asserts that
  inspect and propose resolve zero names. That SPI needs Java 18+, so the task skips with an
  explanation when no such JDK is registered; the extension itself stays on 17.
- **`extensionSmoke`** — initializes `Extension` against a stand-in Montoya API under a temporary
  `user.home`. It is the only check that exercises the Burp wiring, whose failure mode is
  otherwise just "the extension does not load".

Go has `go test -race ./...`, which covers the runtime-status snapshot and the shared proxy state.
The proxy-URL contract is asserted on both sides — `src-go/server/proxyurl_test.go` and
`burp.control.ProxyUrl#main` carry the same table, so a `tls-client` bump that widens or narrows
the accepted set breaks the build rather than changing what the UI accepts.

Everything else is verified manually: load the jar into Burp and check the resulting
fingerprint against `tls.peet.ws` or `scrapfly.io/web-scraping-tools/http2-fingerprint`.

Not covered by any of the above, and required by ADR-0001 section 17.3 before release: the same
MCP flow driven by Codex Desktop and Codex CLI inside a running Burp.

## Architecture

### Request flow

```
Any Burp tool — Proxy, Repeater, Intruder, Scanner, other extensions
  └─> Extension.processHttpRequest (registered via api.http().registerHttpHandler)
        ├─ pass through if already rewritten, or if it is Burp's own traffic
        ├─ settings.toTransportConfig(host)      # defaults + most specific domain rule
        ├─ set Host / Scheme / HeaderOrder       # from the original request
        ├─ gson.toJson -> "Awesometlsconfig" header
        └─ request.withService(spoof server)     # redirect to the local Go server
              │
              v  (HTTPS, self-signed CA)
        Go server handler (server.go:41)
              ├─ ParseTransportConfig(header); strip the header
              ├─ NewClient(config)               # utls / tls-client with the chosen fingerprint
              ├─ restore Host/Scheme, re-apply header order
              └─ forward to the real destination, stream the response back to Burp
```

The key property: **all configuration travels per-request inside the magic header.** The
Go server keeps no per-connection config state, which is why per-domain fingerprints are
implemented entirely in Java — the Go side needed no changes at all.

### Per-domain rules

`FingerprintRule` overrides the global defaults for a hostname; `RuleMatcher` resolves which
one applies. An exact host beats a wildcard, and among wildcards the longest suffix wins, so
the outcome does not depend on row order in the UI. Empty rule fields inherit the defaults.

Two things to preserve when touching this path:

- **`Fingerprint` and `HexClientHello` must be overridden as a pair.** The Go side always
  prefers `HexClientHello`, so a rule setting only `Fingerprint` would be silently ignored
  whenever a global hex ClientHello is configured. `Settings.toTransportConfig` clears the
  other field when either is overridden.
- **`Settings` serves everything from memory.** `toTransportConfig` is on the per-request hot
  path; re-reading `Preferences` or re-parsing the rules JSON there would cost real throughput
  under Intruder/Scanner load. Writes update the cache and the store together, and the cached
  rule list is replaced wholesale (volatile) because the EDT writes it while proxy threads read it.

### Where configuration lives

Two different stores, on purpose:

| What | Where | Why |
|---|---|---|
| Listen address, default fingerprint, timeouts, intercept settings | Burp `Preferences` | A handful of short scalars |
| Domain rules | `rules.json` in the OS config dir, beside the Go side's `ca.der` | Unbounded size, hand-editable, diffable, shareable |

Rules are **not** in `Preferences` because it is backed by the Java preference store, which
rejects any single value over 8192 characters (`java.util.prefs.Preferences.MAX_VALUE_LENGTH`).
Two rules carrying a full ClientHello hex stream already exceed that, and the failure mode is
an exception thrown mid-save — silent data loss. `RuleStore` owns the file: atomic write via
temp-file + rename, previous version kept as `.bak` (saving is automatic, so there is no undo),
and unparseable content preserved as `.corrupt` rather than overwritten.

`RuleStore.configDir()` reimplements Go's `os.UserConfigDir()` — Java has no equivalent — so
both languages resolve to the same directory. Keep them in sync if either side changes: the
directory name lives in `RuleStore.DIR_NAME` and `certificate.go`'s `configDirName`, and the two
must match or the CA and the rules end up in different places.

Both sides also migrate off the pre-`-plus` directory name (`RuleStore.LEGACY_DIR_NAME` /
`legacyConfigDirName`), each moving only its own files: Java takes `rules.json` and its `.bak`,
Go takes `ca.der` and `caKey.der`. The condition is the *file*, not the directory — whichever
side starts first creates the new directory, so a directory-level check would strand the other
side's data in the old location. Both are no-ops once the file is in place, so they are safe to
re-run and cannot overwrite newer state.

Setups predating the file still have rules in `Preferences`; `Settings.loadRulesAtStartup()`
migrates them once and deliberately leaves the old key in place so a downgrade still works.

### The two halves

- `src/main/java/burp/` — Burp extension. `Extension` registers the proxy handler, the
  suite tab, and starts the Go server on a background thread. `Settings` is the composition root
  and the face the Swing UI talks to. `ServerLibrary` is the JNA interface. `SettingsTab` is the
  UI, with `AiControlPanel` as its fourth tab.
- `src/main/java/burp/control/` — `SettingsControl` and everything behind it. Deliberately free of
  Burp and Swing types, which is what lets the failure paths be exercised without either.
- `src-go/server/` — `server.go` (the local HTTPS server + handler), `transport.go`
  (`TransportConfig` + tls-client construction), `hexclienthello.go` (parses a raw
  ClientHello hex stream into a utls spec), `certificate.go` (self-signed CA, cached under
  the OS config dir as `burp-awesome-tls-plus/ca.der`), `intercept.go` (the optional
  fingerprint-sniffing proxy), `cmd/main.go` (cgo exports).

Go module is named `server` (not a domain path); `cmd/main.go` imports it as `"server"`.

### AI Settings Control

[ADR-0001](docs/decisions/0001-ai-settings-control-via-embedded-mcp.md) is the normative contract
for this; read it before changing settings storage, validation, the settings UI, rule matching, MCP
transport, or extension lifecycle. The shape:

```text
Codex Desktop / CLI  ──MCP──>  McpServer (Jetty, 127.0.0.1 only)
                                    │
                               AiSettingsService        SettingsTab / AiControlPanel
                                    └───────> SettingsControl <───────┘
                                                   │
                         Preferences ──── rules.json ──── TransactionJournal / AuditTrail
                                                   │
                                    committed snapshot + matching RuleMatcher
                                                   │
                                            request hot path
```

`SettingsControl` is the single seam. Both adapters — Swing and MCP — go through it, so validation,
revisioning, diffing and persistence cannot fork into near-copies that disagree. The committed
snapshot and its `RuleMatcher` are published together in one `AtomicReference`, so a request thread
sees a whole configuration or the previous whole configuration, never a mixture.

Things that will look like bugs and are not:

- **There is no tool that applies a proposal.** `inspect` and `propose` are the only two.
  Approval, rejection and revert live in the Burp UI. Adding an AI-callable apply is a new
  architecture decision, not a feature.
- **`propose` does write, when auto-apply is armed.** ADR section 22 (approved 2026-08-25) adds a
  Burp-only switch that commits a valid proposal on arrival and returns `status: "APPLIED"`. It
  removes the review step and nothing else: validation, journal, audit, three-way merge and the
  undo all still run, and a dirty settings tab, a moved revision or an unreadable rules file still
  block it. The switch is off by default and confirmed when the user arms it; since ADR section 24
  it is remembered across restarts, and a client still cannot arm it. The
  `tools/list` description and `server/discover` instructions change with it, because a tool that
  claims it never applies settings while auto-apply is armed is worse than no description.
- **Exactly one phase is the commit decision.** `TransactionJournal.Phase.COMMIT_DECIDED`. Before
  it, any failure rolls back; at or after it, nothing rolls back, ever — a change the user approved
  and that was durably decided must not be undone because a phase marker or a UI refresh failed
  afterwards. With full audit on, the durable `MUTATION_COMMITTED` event *is* the decision.
- **"Was it committed?" has three answers.** `AuditTrail.Evidence` is `FOUND`, `ABSENT` or
  `INDETERMINATE`. Collapsing the third into `ABSENT` turns a torn write into a silent rollback.
- **Duplicated rule patterns disable every row claiming that key**, rather than the last one
  winning. This replaced the previous behaviour on purpose; see `RuleMatcher#checkDuplicatesNeverMatch`.
- **`RuleStore.parse` is strict.** A blank file, a null row or an unknown field is now an error,
  not "you have no rules" — because the same file is the base for a three-way merge, and an empty
  baseline silently discards every rule. `RuleStore.probe()` is the only read that may be used for
  inspect, propose, approval or recovery: it has no side effects, where `load()` quarantines.
- **`HostKey` is the only host normalizer.** The request path, the UI, AI patches, the revision and
  the matcher all call it and only switch `Mode`.
- **AI Control's own port, enable state, audit switch and risk acknowledgement are not settings.**
  They do not enter the revision, so enabling the listener cannot invalidate a proposal waiting for
  review. Only the enable state is deliberately not persisted — the listener being closed on every
  start is what bounds the unauthenticated surface. The risk acknowledgement (section 23) and
  auto-apply (section 24) are both stored, because neither does anything until the user has opened
  the listener, and re-collecting the same consent produced no new consent.
- **The request path uses the Go listener's actual address**, via `Settings#activeSpoofProxyAddress`,
  not the configured one. Changing the address does not move a running server.

## Non-obvious constraints

**`TransportConfig` is duplicated in both languages and matched by field name.**
`TransportConfig.java` and the struct in `transport.go` must stay in sync — gson serializes
using the Java field names (hence the unusual capitalized public fields) and Go's
`encoding/json` matches them case-insensitively. Renaming a field on one side only causes
a *silent* fallback to the zero value, not an error.

**The magic header name has a hard format restriction.** `Awesometlsconfig` — one leading
capital, rest lowercase. Burp's Extender API mangles anything else (see `server.go:14-16`).

**The handler re-enters itself.** The rewritten request is sent *by Burp*, so it arrives back at
`handleHttpRequestToBeSent` — an `HttpHandler` sees every outgoing request, unlike the
`ProxyRequestHandler` this used to be. The presence of the `Awesometlsconfig` header is what
marks a request as already handled; drop that guard and every request rewrites itself forever.
Burp's own traffic (`ToolType.SUITE` — update checks, Collaborator polling) is passed through
too, since redirecting it through the spoof server would break it.

**The READMEs and `docs/**.md` are also a published website.** GitHub Pages builds
<https://robin528919.github.io/burp-awesome-tls-plus/> from `main`'s root via Jekyll, so
`README.md` *is* the site index and every other markdown file becomes a page in `sitemap.xml`.
Editing docs silently redeploys the site. Two root files drive it: `_config.yml` (theme,
plugins, `exclude` list for build artefacts) and `_includes/head-custom.html` — the cayman
layout already emits `{% seo %}`, so that include holds only the JSON-LD and the `llms.txt`
pointer, and adding a second seo tag there would duplicate every meta tag. Relative `.md`
links are rewritten to `.html` by `jekyll-relative-links`; don't hand-write `.html` targets.
The site exists because the GitHub repo page cannot be verified in Search Console and this can
— see `docs/posts/` for the same reason.

**The UI is hand-written Swing — do not reintroduce a `.form` file.** The IntelliJ GUI
designer form was removed (along with the `com.intellij:forms_rt` dependency) because it was
never wired into Gradle: there was no `javac2` instrumentation, so `SettingsTab.form` could
only be turned into code from inside the IDE, and the generated `$$$setupUI$$$()` was a
committed build artifact that silently overwrote hand edits. `SettingsTab` now builds its
layout directly.

**Burp disables Swing's HTML rendering.** `new JLabel("<html>…")` displays the markup as
literal text, so the usual trick for wrapping or emphasising label copy does not work. Use
`SettingsTab.descriptionText()` (a borderless, non-editable wrapping `JTextArea`) for anything
longer than one line.

**Let Burp style the UI: `api.userInterface().applyThemeToComponent(component)`.** It applies
Burp's font size, colors and table line spacing for the active theme, and is called once on the
root panel in `Extension`. Never hardcode colors — Burp ships light and dark themes, and a fixed
color renders black-on-black under the dark one. `SettingsTab`'s `UIManager` helpers exist only
as a fallback for components Burp's pass does not reach. Related: `currentTheme()` returns
`LIGHT`/`DARK` if you ever need to branch.

**Burp's official settings-panel API does not fit this extension.** `SettingsPanelBuilder`
(registered via `registerSettingsPanel`) gives you Burp-native styling and persistence for free,
but only supports scalars — `stringSetting` / `integerSetting` / `booleanSetting` /
`listSetting`. There is no table type, so the domain rules cannot use it, and splitting the
config across `Settings > Extensions` and a suite tab would be worse than one coherent tab.
Do not migrate without re-checking whether a table setting has been added.

**Fields need a trailing filler column.** Burp's window is very wide; a `weightx=1` text field
stretches across all of it. `FormPanel` gives fields their natural width and lets a filler
column absorb the slack.

**The intercept proxy is global mutable state.** `server.go:51-63` starts/stops it based on
the `UseInterceptedFingerprint` flag of whichever request arrives. If that flag ever varies
between requests, the proxy will thrash (rebinding its port, cutting live connections).
It must stay a single global setting.

**A new tls-client is constructed per request** (`transport.go:126`) — no connection pooling
or client reuse across requests.

**Fingerprint precedence** (`transport.go:75-124`): intercepted ClientHello > `HexClientHello`
> named `Fingerprint` profile. The named profiles come from `profiles.MappedTLSClients`
(~79 entries) and are surfaced to Java as a newline-joined string via `GetFingerprints()`.

**Errors from the intercept proxy reach Burp as a fake HTTP request** to host
`awesome-tls-error` (`intercept.go:207-224`), which `Extension.java:66-68` recognizes and
re-throws. Don't treat that hostname as a real destination.
