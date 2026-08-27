package burp.control;

import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The commands and configuration blobs the AI Control tab copies to the clipboard.
 * <p>
 * These are not UI copy. They are shell commands a user pastes into a terminal and JSON a user
 * pastes into a client's config file, and every one of them fails silently when wrong: a mistyped
 * path installs the skill where nothing reads it, and the wrong JSON key is ignored by the client
 * exactly the way never having configured it is. Neither produces an error anyone sees.
 * <p>
 * Kept free of Swing and the Burp API so {@link #main} can assert the whole set without a running
 * Burp — the alternative is a person clicking six buttons and reading their clipboard, which is
 * how the previous Codex line went on appending to {@code AGENTS.md} for months after Codex had
 * started reading {@code SKILL.md}.
 * <p>
 * The skill paths are an open standard rather than any one client's convention, which is the whole
 * reason there is no button per client: {@code ~/.claude/skills} and {@code ~/.agents/skills} are
 * both scanned by Claude Code, OpenCode, Cursor, Copilot and Gemini CLI, and Codex adds
 * {@code ~/.codex/skills}. Three paths cover a field of dozens. See ADR-0001 section 27.1.
 */
public final class ClientSnippets {

    /** Which snippet to produce. One per button in the tab's *Connect a client* section. */
    public enum Kind {
        /** The bare endpoint URL. */
        ENDPOINT,
        /** `claude mcp add …`, registered globally. */
        CLAUDE_CODE,
        /** `codex mcp add …`. */
        CODEX,
        /** The `mcpServers` shape most hand-configured clients expect. */
        JSON,
        /** OpenCode's shape, which shares no key with the one above. */
        JSON_OPENCODE,
        /** Installs the skill to the two paths every agent scans. */
        SKILL,
        /** Installs the skill to Codex's own path. */
        CODEX_SKILL,
    }

    private ClientSnippets() {
    }

    /**
     * @param kind       which snippet
     * @param serverName what the server is called in a client's configuration
     * @param endpoint   the endpoint a client should be pointed at
     * @param skillUrl   where {@code SKILL.md} is served from
     */
    public static String of(Kind kind, String serverName, String endpoint, String skillUrl) {
        return switch (kind) {
            case ENDPOINT -> endpoint;
            case CLAUDE_CODE -> "claude mcp add --transport http --scope user "
                    + serverName + " " + endpoint;
            case CODEX -> "codex mcp add " + serverName + " --url " + endpoint;
            // The shape most clients that are configured by hand expect. Keys vary between
            // clients, so this is a starting point rather than a guarantee.
            case JSON -> "{\n"
                    + "  \"mcpServers\": {\n"
                    + "    \"" + serverName + "\": {\n"
                    + "      \"type\": \"http\",\n"
                    + "      \"url\": \"" + endpoint + "\"\n"
                    + "    }\n"
                    + "  }\n"
                    + "}";
            // OpenCode uses its own key and value here: "mcp" rather than "mcpServers", and
            // "remote" rather than "http". Pasting the shape above into opencode.json is silently
            // ignored, which is the same failure mode as never having configured it.
            case JSON_OPENCODE -> "{\n"
                    + "  \"mcp\": {\n"
                    + "    \"" + serverName + "\": {\n"
                    + "      \"type\": \"remote\",\n"
                    + "      \"url\": \"" + endpoint + "\",\n"
                    + "      \"enabled\": true\n"
                    + "    }\n"
                    + "  }\n"
                    + "}";
            // One SKILL.md, downloaded once and copied rather than fetched twice. Kept separate
            // from the Codex line because ~/.codex/skills is Codex's own path, and creating it on
            // a machine without Codex would just leave litter behind.
            case SKILL -> "mkdir -p ~/.claude/skills/awesome-tls-mcp "
                    + "~/.agents/skills/awesome-tls-mcp"
                    + " && curl -fsSL -o ~/.claude/skills/awesome-tls-mcp/SKILL.md " + skillUrl
                    + " && cp ~/.claude/skills/awesome-tls-mcp/SKILL.md "
                    + "~/.agents/skills/awesome-tls-mcp/SKILL.md";
            // Overwrites rather than appends. This used to append to ~/.codex/AGENTS.md, which
            // made 160 lines of reference material into a permanent global instruction and left a
            // second copy every time it was run; Codex has read SKILL.md since December 2025.
            case CODEX_SKILL -> "mkdir -p ~/.codex/skills/awesome-tls-mcp && curl -fsSL -o "
                    + "~/.codex/skills/awesome-tls-mcp/SKILL.md " + skillUrl;
        };
    }

    /** Self-check: every snippet is well-formed and carries the values it was given. */
    public static void main(String[] args) throws IOException {
        var name = "awesome-tls";
        var endpoint = "http://127.0.0.1:8885/mcp";
        var url = "https://example.invalid/SKILL.md";

        for (var kind : Kind.values()) {
            var text = of(kind, name, endpoint, url);
            assertThat(text != null && !text.isBlank(), kind + " is blank");
            assertThat(text.equals(text.strip()), kind + " has stray leading/trailing whitespace");
        }

        // Every snippet that points a client somewhere must carry the endpoint verbatim. A
        // snippet that silently drops it looks correct and configures nothing.
        for (var kind : new Kind[]{Kind.ENDPOINT, Kind.CLAUDE_CODE, Kind.CODEX, Kind.JSON,
                Kind.JSON_OPENCODE}) {
            assertThat(of(kind, name, endpoint, url).contains(endpoint),
                    kind + " does not carry the endpoint");
        }
        for (var kind : new Kind[]{Kind.SKILL, Kind.CODEX_SKILL}) {
            assertThat(of(kind, name, endpoint, url).contains(url),
                    kind + " does not carry the skill URL");
        }

        // The two JSON shapes share no key. Producing one where the other is expected is the
        // failure this asserts against, and it is invisible at the client end.
        var json = of(Kind.JSON, name, endpoint, url);
        assertThat(parses(json), "JSON is not valid JSON");
        assertThat(json.contains("\"mcpServers\"") && json.contains("\"type\": \"http\""),
                "JSON lost the mcpServers/http shape");
        assertThat(!json.contains("\"mcp\":"), "JSON must not use OpenCode's key");

        var opencode = of(Kind.JSON_OPENCODE, name, endpoint, url);
        assertThat(parses(opencode), "JSON_OPENCODE is not valid JSON");
        assertThat(opencode.contains("\"mcp\"") && opencode.contains("\"type\": \"remote\""),
                "JSON_OPENCODE lost the mcp/remote shape");
        assertThat(!opencode.contains("mcpServers"), "JSON_OPENCODE must not use the generic key");
        assertThat(opencode.contains("\"enabled\": true"),
                "JSON_OPENCODE must enable the server; OpenCode does not default it on");

        // ADR-0001 section 27.1. Both paths, or the skill is invisible to whichever client only
        // scans the missing one.
        var skill = of(Kind.SKILL, name, endpoint, url);
        assertThat(skill.contains("~/.claude/skills/awesome-tls-mcp/SKILL.md"),
                "SKILL lost the ~/.claude/skills path");
        assertThat(skill.contains("~/.agents/skills/awesome-tls-mcp/SKILL.md"),
                "SKILL lost the ~/.agents/skills path");

        // The regression this file exists for: Codex reads SKILL.md, and appending the skill to
        // its AGENTS.md turns reference material into a permanent global instruction that gains a
        // duplicate on every run. Both the file and the append operator are refused here.
        var codexSkill = of(Kind.CODEX_SKILL, name, endpoint, url);
        assertThat(codexSkill.contains("~/.codex/skills/awesome-tls-mcp/SKILL.md"),
                "CODEX_SKILL lost the ~/.codex/skills path");
        assertThat(!codexSkill.contains("AGENTS.md"),
                "CODEX_SKILL must not write AGENTS.md; Codex reads SKILL.md");
        for (var install : new String[]{skill, codexSkill}) {
            assertThat(!install.contains(">>"),
                    "an install line must overwrite, not append: " + install);
            assertThat(install.contains("curl -fsSL -o "),
                    "an install line must download to a path, not to stdout: " + install);
        }

        checkReadmes();

        System.out.println("Client snippet self-check passed");
    }

    /**
     * The READMEs publish the same two install commands, and they are the site's front page — a
     * wrong command there reaches users directly, with no button to compare it against.
     * <p>
     * This is not hypothetical: the panel's Codex line was corrected to write {@code ~/.codex/skills}
     * while both READMEs went on publishing the {@code >> ~/.codex/AGENTS.md} append for a while
     * afterwards. Only the shell commands are compared — the JSON blocks are re-indented for
     * markdown and would not match literally.
     */
    private static void checkReadmes() throws IOException {
        // What the READMEs document: the default port, and the skill served from main.
        var endpoint = "http://127.0.0.1:" + 8885 + "/mcp";
        var skillUrl = "https://raw.githubusercontent.com/Robin528919/"
                + "burp-awesome-tls-plus/main/skills/awesome-tls-mcp/SKILL.md";

        for (var name : new String[]{"README.md", "README.zh-CN.md"}) {
            var path = Path.of(name);
            if (!Files.isRegularFile(path)) {
                // Run from somewhere other than the repository root. Nothing to compare against.
                System.out.println("  (" + name + " not found; skipped)");
                continue;
            }
            var text = Files.readString(path);
            for (var kind : new Kind[]{Kind.SKILL, Kind.CODEX_SKILL}) {
                assertThat(text.contains(of(kind, "awesome-tls", endpoint, skillUrl)),
                        name + " does not publish the current " + kind + " command");
            }
            assertThat(!text.contains(">> ~/.codex/AGENTS.md"),
                    name + " still publishes the append-to-AGENTS.md install");
        }
    }

    private static boolean parses(String json) {
        try {
            return JsonParser.parseString(json).isJsonObject();
        } catch (JsonSyntaxException e) {
            return false;
        }
    }

    private static void assertThat(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
