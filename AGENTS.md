# Repository Guidelines

## Project Structure & Architecture

`src/main/java/burp/` contains the Java 17 Burp extension, Swing settings UI, rule matching, and JNA bridge. `src-go/server/` contains the native TLS proxy; `cmd/main.go` exports the shared-library entry points. Compiled native libraries belong under `src/main/resources/<jna-platform>/` and are intentionally ignored. Documentation and screenshots live in `docs/`; root Markdown files and `docs/**/*.md` are also published through GitHub Pages.

Requests are rewritten in Java, carry per-request JSON in the `Awesometlsconfig` header, and are forwarded by the local Go server. Keep `TransportConfig.java` and the Go `TransportConfig` struct field-for-field compatible. Keep Java and Go configuration-directory constants synchronized.

## AI Settings Control Direction (Locked)

The normative design and acceptance contract is [ADR-0001: AI Settings Control via Embedded MCP](docs/decisions/0001-ai-settings-control-via-embedded-mcp.md). Read it before changing settings storage, validation, the Swing settings UI, rule matching, MCP transport, or extension lifecycle. Its accepted decisions are locked; changing them requires explicit user approval and an ADR update.

The non-negotiable core is:

- Embed a local MCP adapter in the Burp extension. Expose only `awesome_tls.settings.inspect` and `awesome_tls.settings.propose`; applying, rejecting, and reverting remain local Burp UI actions. Never add an AI-callable apply/commit path, direct Preferences/file writes, or raw `TransportConfig` mutation.
- Put Swing and MCP behind one `SettingsControl` seam with shared validation, canonical revisioning, diffing, persistence, runtime-impact classification, and an immutable snapshot plus matching `RuleMatcher` published atomically.
- Preserve the scalar-Preferences/domain-`rules.json` storage split, but add staged persistence, compensation, and startup recovery. Never publish a partially persisted runtime snapshot or silently use last-write-wins.
- Treat configured and active listener state separately. In particular, request rewriting must continue to use the Go listener's actual active address until the extension is reloaded.
- Target MCP `2026-07-28`, keep Java 17, and validate the chosen embedded HTTP engine inside the real Burp runtime before locking it in. Do not downgrade the protocol or present an older SDK as 2026-compatible.
- AI Control is session-enabled, unauthenticated, bound only to literal `127.0.0.1`, checks the exact `Host`, and rejects every `/mcp` request carrying `Origin`. It returns full proxy credentials and raw ClientHello values without redaction. The UI must warn on every enable that any local process can read them.
- Do not expand or rename the Java/Go `TransportConfig` contract for this feature. Any authentication mode, browser/remote client support, unattended apply, different protocol version, or storage migration is a new architecture decision.

## Build, Test, and Development Commands

- `cd src-go/server && go build -buildmode=c-shared -o ../../src/main/resources/darwin-aarch64/libserver.dylib ./cmd/main.go` builds the native library for Apple Silicon. Use the platform mapping in `README.md` elsewhere.
- `./gradlew buildJar` creates `build/libs/burp-awesome-tls-plus.jar`; build the Go library first.
- `cd src-go/server && go test ./...` compiles and runs any Go tests.
- `./gradlew compileJava` performs the Java compile check.
- `./build.sh` packages all platform-specific and fat jars, but only after CI/xgo-style outputs exist in `src-go/server/build/`.

## Coding Style & Naming

Use four-space indentation and existing package-private boundaries in Java. Classes use `PascalCase`; methods and locals use `camelCase`. Preserve the intentionally capitalized Java transport fields because Gson maps them to Go. Format Go changes with `gofmt`; use tabs and standard Go naming. Keep Swing UI hand-written—do not add IntelliJ `.form` files or hard-coded theme colors.

## Testing Guidelines

There is no conventional test suite or coverage threshold yet. Add focused `_test.go` or `src/test/java` tests when practical. Existing Java regression checks are executable `main` methods in `RuleMatcher` and `RuleStore`; run them with assertions as documented in `CLAUDE.md`. For request-path changes, load the jar in Burp and verify the observed TLS/HTTP2 fingerprint against an authorized test endpoint.

## Commits & Pull Requests

Follow the repository's Conventional Commit pattern, for example `feat(rules): ...`, `fix(ui): ...`, `docs(site): ...`, or `ci: ...`. Keep commits scoped. Pull requests should explain behavior and compatibility impact, link relevant issues, list exact validation commands, and include screenshots for UI or rendered-documentation changes. Call out any Java/Go contract change explicitly.

## Security & Configuration

Use this extension only against systems you own or are authorized to test. Never commit credentials, certificates, generated native binaries, or local `rules.json` data.
