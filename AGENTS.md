# Repository Guidelines

## Project Structure & Architecture

`src/main/java/burp/` contains the Java 17 Burp extension, Swing settings UI, rule matching, and JNA bridge. `src/main/java/burp/control/` contains `SettingsControl` and the AI Settings Control stack, deliberately free of Burp and Swing types. `src/test/java/probe/` holds the two probes that need a stand-in Burp API or a Java 18+ resolver SPI. `src-go/server/` contains the native TLS proxy; `cmd/main.go` exports the shared-library entry points. Compiled native libraries belong under `src/main/resources/<jna-platform>/` and are intentionally ignored. Documentation and screenshots live in `docs/`; root Markdown files and `docs/**/*.md` are also published through GitHub Pages.

Requests are rewritten in Java, carry per-request JSON in the `Awesometlsconfig` header, and are forwarded by the local Go server. Keep `TransportConfig.java` and the Go `TransportConfig` struct field-for-field compatible. Keep Java and Go configuration-directory constants synchronized.

## AI Settings Control (Locked, implemented)

The normative design and acceptance contract is [ADR-0001: AI Settings Control via Embedded MCP](docs/decisions/0001-ai-settings-control-via-embedded-mcp.md). Read it before changing settings storage, validation, the Swing settings UI, rule matching, MCP transport, or extension lifecycle. Its accepted decisions are locked; changing them requires explicit user approval and an ADR update.

It is implemented. The embedded HTTP engine is Jetty 12 core, chosen by the section 16.5 spike: Burp's bundled runtime is a JRE 24 **without `jdk.httpserver`**, so `com.sun.net.httpserver` is unavailable, and Jetty core needs no servlet container. Outstanding before release: the section 17.3 end-to-end run with Codex Desktop and Codex CLI inside a real Burp, which cannot be automated here.

The ADR has been amended four times, with explicit approval; see its sections 22 to 25. Do not treat "the AI can never change settings" as still true without qualification, and do not remove the auto-apply switch's remaining constraints — off by default, confirmed when armed, armable only from Burp — as tidying.

The non-negotiable core is:

- Embed a local MCP adapter in the Burp extension. Expose only `awesome_tls.settings.inspect` and `awesome_tls.settings.propose`. Never add an AI-callable apply/commit path, direct Preferences/file writes, or raw `TransportConfig` mutation.
- **Auto-apply (ADR §22, amended by §24).** A Burp-only switch makes a valid `propose` commit immediately, returning `status: "APPLIED"`. It removes the review step and nothing else — every validation, the journal, the audit trail, the three-way merge and the undo all still run. It is off by default and confirmed when the user arms it; since §24 it is remembered across restarts. There is still no AI-callable way to apply, approve, reject or revert, and no way for a client to arm it.
- **Only the listener is session-only (ADR §5, §23, §24).** The endpoint is closed on every start and only the user can open it. That is what bounds the unauthenticated surface — not the arming, and not the acknowledgement, both of which are stored. Do not restore either to session-only as a security tidy-up; read §23.3 and §24.3 first.
- Put Swing and MCP behind one `SettingsControl` seam with shared validation, canonical revisioning, diffing, persistence, runtime-impact classification, and an immutable snapshot plus matching `RuleMatcher` published atomically.
- Preserve the scalar-Preferences/domain-`rules.json` storage split, but add staged persistence, compensation, and startup recovery. Never publish a partially persisted runtime snapshot or silently use last-write-wins.
- Treat configured and active listener state separately. In particular, request rewriting must continue to use the Go listener's actual active address until the extension is reloaded.
- Target MCP `2026-07-28`, keep Java 17, and validate the chosen embedded HTTP engine inside the real Burp runtime before locking it in. Do not downgrade the protocol or present an older SDK as 2026-compatible.
- AI Control is session-enabled, unauthenticated, bound only to literal `127.0.0.1`, checks the exact `Host`, and rejects every `/mcp` request carrying `Origin`. It returns full proxy credentials and raw ClientHello values without redaction. The UI must warn on every enable that any local process can read them.
- Do not expand or rename the Java/Go `TransportConfig` contract for this feature. Any authentication mode, browser/remote client support, unattended apply, different protocol version, or storage migration is a new architecture decision.

## Build, Test, and Development Commands

- `cd src-go/server && go build -buildmode=c-shared -o ../../src/main/resources/darwin-aarch64/libserver.dylib ./cmd/main.go` builds the native library for Apple Silicon. Use the platform mapping in `README.md` elsewhere.
- `./gradlew buildJar` creates `build/libs/burp-awesome-tls-plus.jar`; build the Go library first.
- `cd src-go/server && go test -race ./...` runs the Go tests, including the runtime-status race gate and the proxy-URL golden vectors that must agree with `burp.control.ProxyUrl`.
- `./gradlew compileJava` performs the Java compile check.
- `./gradlew checkAll` runs every self-check, the no-DNS probe, and the extension smoke test.
- `./build.sh` packages all platform-specific and fat jars, but only after CI/xgo-style outputs exist in `src-go/server/build/`.

## Coding Style & Naming

Use four-space indentation and existing package-private boundaries in Java. Classes use `PascalCase`; methods and locals use `camelCase`. Preserve the intentionally capitalized Java transport fields because Gson maps them to Go. Format Go changes with `gofmt`; use tabs and standard Go naming. Keep Swing UI hand-written—do not add IntelliJ `.form` files or hard-coded theme colors.

## Testing Guidelines

There is no conventional test suite or coverage threshold. Java checks are executable `main` methods, registered in `build.gradle` and run together with `./gradlew checkAll`; add a new one to the `selfChecks` list so it cannot quietly stop running. Keep a check in the class it exercises, following the existing pattern. For request-path changes, load the jar in Burp and verify the observed TLS/HTTP2 fingerprint against an authorized test endpoint.

Three invariants are easy to break and hard to notice, so they have dedicated checks: `SettingsControlCheck` for the commit-decision boundary, `AiSettingsServiceCheck` for what an AI may and may not do, and `McpServerCheck` for the wire contract. Do not weaken an assertion in these to make a change pass.

## Commits & Pull Requests

Follow the repository's Conventional Commit pattern, for example `feat(rules): ...`, `fix(ui): ...`, `docs(site): ...`, or `ci: ...`. Keep commits scoped. Pull requests should explain behavior and compatibility impact, link relevant issues, list exact validation commands, and include screenshots for UI or rendered-documentation changes. Call out any Java/Go contract change explicitly.

## Security & Configuration

Use this extension only against systems you own or are authorized to test. Never commit credentials, certificates, generated native binaries, or local `rules.json` data.
