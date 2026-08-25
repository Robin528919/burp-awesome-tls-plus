package burp.control;

import burp.FingerprintRule;
import burp.RuleStore;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Conformance self-check for the MCP endpoint, run against a real listener on loopback.
 * <p>
 * Covers the fixed HTTP/JSON-RPC mapping of ADR-0001 section 15 row by row, the header contract of
 * section 16.1, and the published tool definitions of section 16.2. Those are a contract with
 * clients that are configured once and then left alone, so a silent change to any of them shows up
 * as a client that stops working for no visible reason.
 * <p>
 * What this cannot cover is the other half of section 17.3: the same flow driven by Codex Desktop
 * and Codex CLI inside a running Burp. That gate needs those products and is not automatable here.
 * <p>
 * Run with:
 * {@code java -ea -cp build/classes/java/main:<gson.jar>:<jetty jars> burp.control.McpServerCheck}
 */
public final class McpServerCheck {
    private static HttpClient client;
    private static int port;
    private static String base;

    private McpServerCheck() {
    }

    public static void main(String[] args) throws Exception {
        // The Host header is restricted by default, and a wrong-Host request is the point of one
        // of the gates below.
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        // A dedicated pool: the default executor would read both slow request bodies on the same
        // thread, so only one of them would ever be in flight and the concurrency ceiling could
        // not be reached.
        client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .executor(java.util.concurrent.Executors.newFixedThreadPool(8, runnable -> {
                    var thread = new Thread(runnable, "mcp-check-client");
                    thread.setDaemon(true);
                    return thread;
                }))
                .build();

        var fixture = Fixture.create();
        port = freePort();
        fixture.server.start(port);
        base = "http://127.0.0.1:" + port + McpServer.PATH;

        try {
            check(fixture.server.running(), "the listener starts");
            check(fixture.server.endpoint().equals(base), "and reports its endpoint");

            methodsOtherThanPostAreRefused();
            hostGate();
            originGate();
            framingGates();
            protocolVersionGate();
            envelopeGates();
            headerBodyAgreement();
            unknownMethod();
            ignoredHeaders();
            discoverIsFixed();
            toolsListIsFixed(fixture);
            inspectRoundTrip(fixture);
            proposeRoundTrip(fixture);
            businessErrorsAreResultsNotProtocolErrors(fixture);
            noCorsHeaders();
            bodyTooLarge();
            concurrencyCeiling(fixture);
            rateLimit(fixture);
        } finally {
            fixture.server.stop();
        }

        check(!fixture.server.running(), "the listener stops");
        check(portIsFree(port), "and releases its port");

        restartAndBindConflict(fixture);

        System.out.println("McpServer conformance self-check passed");
    }

    // ------------------------------------------------------------------ gates

    private static void methodsOtherThanPostAreRefused() throws Exception {
        for (var method : List.of("GET", "DELETE", "PUT")) {
            var response = send(HttpRequest.newBuilder(URI.create(base))
                    .method(method, HttpRequest.BodyPublishers.noBody()));
            check(response.statusCode() == 405, method + " is refused with 405");
        }
        // No legacy standalone stream and no protocol session.
        check(send(HttpRequest.newBuilder(URI.create(base)).GET()).headers()
                .firstValue("Mcp-Session-Id").isEmpty(), "no session id is ever issued");
    }

    private static void hostGate() throws Exception {
        var wrong = post(discoverBody()).header("Host", "evil.example.com:" + port);
        var response = send(wrong);
        check(response.statusCode() == 403, "a wrong Host is refused with 403");
        var error = errorOf(response);
        check(error.get("code").getAsInt() == McpServer.CODE_GATE_REJECTED, "with the gate code");
        check(error.getAsJsonObject("data").get("code").getAsString().equals("HOST_REJECTED"),
                "identified as a Host rejection");
        check(!body(response).has("id"), "and no id is invented for it");

        check(send(post(discoverBody()).header("Host", "127.0.0.1:1")).statusCode() == 403,
                "a right host with the wrong port is still wrong");
        check(send(post(discoverBody())).statusCode() == 200, "the exact Host is accepted");
    }

    private static void originGate() throws Exception {
        for (var origin : List.of("http://localhost", "null", "")) {
            var response = send(post(discoverBody()).header("Origin", origin));
            check(response.statusCode() == 403, "Origin \"" + origin + "\" is refused");
            check(errorOf(response).getAsJsonObject("data").get("code").getAsString()
                    .equals("ORIGIN_REJECTED"), "as an Origin rejection, without comparing its value");
        }
    }

    private static void framingGates() throws Exception {
        var wrongType = send(base().header("Content-Type", "text/plain")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(discoverBody())));
        check(wrongType.statusCode() == 415, "a non-JSON Content-Type is refused with 415");
        check(errorOf(wrongType).get("code").getAsInt() == McpServer.CODE_UNSUPPORTED_MEDIA_TYPE,
                "with the media type code");
        check(errorOf(wrongType).getAsJsonObject("data").get("code").getAsString()
                .equals("UNSUPPORTED_MEDIA_TYPE"), "and its data code");

        var charset = send(base().header("Content-Type", "application/json; charset=utf-8")
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", McpServer.PROTOCOL_VERSION)
                .header("Mcp-Method", "server/discover")
                .POST(HttpRequest.BodyPublishers.ofString(discoverBody())));
        check(charset.statusCode() == 200, "a charset parameter is allowed");

        // A repeated required header has no single value, so it is a mismatch rather than a choice.
        var repeated = send(post(discoverBody()).header("Content-Type", "application/json"));
        check(repeated.statusCode() == 415, "a repeated Content-Type is refused");

        var encoded = send(post(discoverBody()).header("Content-Encoding", "gzip"));
        check(encoded.statusCode() == 415, "a compressed body is refused");

        for (var accept : List.of("application/json", "text/event-stream", "*/*")) {
            var response = send(base().header("Content-Type", "application/json")
                    .header("Accept", accept)
                    .POST(HttpRequest.BodyPublishers.ofString(discoverBody())));
            check(response.statusCode() == 406, "Accept \"" + accept + "\" alone is not enough");
            check(errorOf(response).getAsJsonObject("data").get("code").getAsString()
                    .equals("NOT_ACCEPTABLE"), "reported as not acceptable");
        }
    }

    private static void protocolVersionGate() throws Exception {
        for (var version : List.of("2025-11-25", "2026-01-01", "")) {
            var response = send(base().header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .header("MCP-Protocol-Version", version)
                    .header("Mcp-Method", "server/discover")
                    .POST(HttpRequest.BodyPublishers.ofString(discoverBody())));
            check(response.statusCode() == 400, "protocol version \"" + version + "\" is refused");
            var error = errorOf(response);
            check(error.get("code").getAsInt() == McpServer.CODE_UNSUPPORTED_PROTOCOL_VERSION,
                    "with the version code");
            check(error.getAsJsonObject("data").get("requested").getAsString().equals(version),
                    "echoing what was asked for");
            check(error.getAsJsonObject("data").getAsJsonArray("supported").get(0).getAsString()
                    .equals(McpServer.PROTOCOL_VERSION), "and naming what is supported");
        }
    }

    private static void envelopeGates() throws Exception {
        var malformed = send(post("{ not json"));
        check(malformed.statusCode() == 400 && errorOf(malformed).get("code").getAsInt()
                == McpServer.CODE_PARSE_ERROR, "malformed JSON is a parse error");

        var notObject = send(post("[]"));
        check(notObject.statusCode() == 400, "a JSON array envelope is refused");

        var wrongVersion = send(post("{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"server/discover\"}"));
        check(wrongVersion.statusCode() == 400 && errorOf(wrongVersion).get("code").getAsInt()
                == McpServer.CODE_INVALID_REQUEST, "a wrong jsonrpc version is an invalid request");

        // A notification changes nothing and is refused, with no id echoed.
        var notification = send(post("{\"jsonrpc\":\"2.0\",\"method\":\"server/discover\"}"));
        check(notification.statusCode() == 400, "a notification is refused");
        var error = errorOf(notification);
        check(error.get("code").getAsInt() == McpServer.CODE_UNSUPPORTED_NOTIFICATION,
                "with the notification code");
        check(error.getAsJsonObject("data").get("code").getAsString().equals("UNSUPPORTED_NOTIFICATION"),
                "and its data code");
        check(!body(notification).has("id"), "and no id, because a notification has none");
    }

    private static void headerBodyAgreement() throws Exception {
        var mismatched = send(withMethod("tools/list", discoverBody()));
        check(mismatched.statusCode() == 400, "a Mcp-Method that disagrees with the body is refused");
        check(errorOf(mismatched).get("code").getAsInt() == McpServer.CODE_HEADER_MISMATCH,
                "as a header mismatch");

        var missing = send(base().header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", McpServer.PROTOCOL_VERSION)
                .POST(HttpRequest.BodyPublishers.ofString(discoverBody())));
        check(missing.statusCode() == 400 && errorOf(missing).get("code").getAsInt()
                == McpServer.CODE_HEADER_MISMATCH, "a missing Mcp-Method is a mismatch too");

        var call = callBody(McpServer.TOOL_INSPECT, "{\"schemaVersion\":\"" + Wire.SCHEMA_VERSION + "\"}");
        var wrongName = send(withMethod("tools/call", call).header("Mcp-Name", McpServer.TOOL_PROPOSE));
        check(wrongName.statusCode() == 400 && errorOf(wrongName).get("code").getAsInt()
                == McpServer.CODE_HEADER_MISMATCH, "a Mcp-Name naming another tool is a mismatch");

        var noName = send(withMethod("tools/call", call));
        check(noName.statusCode() == 400, "tools/call without Mcp-Name is refused");

        // The base64 sentinel form has to decode to the same name.
        var encoded = "=?base64?" + java.util.Base64.getEncoder()
                .encodeToString(McpServer.TOOL_INSPECT.getBytes(java.nio.charset.StandardCharsets.UTF_8)) + "?=";
        check(send(withMethod("tools/call", call).header("Mcp-Name", encoded)).statusCode() == 200,
                "an encoded Mcp-Name that decodes correctly is accepted");
        check(send(withMethod("tools/call", call).header("Mcp-Name", "=?base64?!!!?=")).statusCode() == 400,
                "a malformed encoding is refused rather than compared literally");

        // The header contract is checked before dispatch, so an unimplemented method still reports
        // the mismatch rather than a confusing method-not-found.
        var read = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"resources/read\","
                + "\"params\":{\"uri\":\"file:///x\"}}";
        var readMismatch = send(withMethod("resources/read", read).header("Mcp-Name", "file:///other"));
        check(readMismatch.statusCode() == 400 && errorOf(readMismatch).get("code").getAsInt()
                == McpServer.CODE_HEADER_MISMATCH,
                "resources/read validates Mcp-Name against params.uri before answering 404");
        var readOk = send(withMethod("resources/read", read).header("Mcp-Name", "file:///x"));
        check(readOk.statusCode() == 404, "and then reports the method as unimplemented");
    }

    private static void unknownMethod() throws Exception {
        var response = send(withMethod("nope/whatever",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"nope/whatever\"}"));
        check(response.statusCode() == 404, "an unknown method is 404");
        check(errorOf(response).get("code").getAsInt() == McpServer.CODE_METHOD_NOT_FOUND,
                "with method-not-found");
        check(body(response).get("id").getAsInt() == 1, "echoing the request id");
    }

    private static void ignoredHeaders() throws Exception {
        var response = send(post(discoverBody())
                .header("Last-Event-ID", "42")
                .header("Mcp-Session-Id", "whatever"));
        check(response.statusCode() == 200, "Last-Event-ID and a session id are ignored, not refused");
        check(response.headers().firstValue("Mcp-Session-Id").isEmpty(), "and never echoed");
    }

    // ------------------------------------------------------------------ methods

    private static void discoverIsFixed() throws Exception {
        var result = body(send(post(discoverBody()))).getAsJsonObject("result");
        check(result.get("resultType").getAsString().equals("complete"), "discover is a complete result");
        check(result.getAsJsonArray("supportedVersions").size() == 1
                && result.getAsJsonArray("supportedVersions").get(0).getAsString()
                .equals(McpServer.PROTOCOL_VERSION), "advertising exactly one protocol version");
        check(!result.getAsJsonObject("capabilities").getAsJsonObject("tools")
                .get("listChanged").getAsBoolean(), "and no list-changed notifications");
        check(result.getAsJsonObject("_meta").getAsJsonObject("io.modelcontextprotocol/serverInfo")
                .get("name").getAsString().equals("burp-awesome-tls-plus"), "with the server name");
        check(result.get("instructions").getAsString().contains("only in the Burp AI Control tab"),
                "and instructions that say where approval happens");
        check(result.get("ttlMs").getAsInt() == 0 && result.get("cacheScope").getAsString()
                .equals("private"), "marked uncacheable and private");
    }

    private static void toolsListIsFixed(Fixture fixture) throws Exception {
        var result = body(send(withMethod("tools/list", listBody()))).getAsJsonObject("result");
        check(!result.has("nextCursor"), "the tool list is not paginated");

        var tools = result.getAsJsonArray("tools");
        check(tools.size() == 2, "exactly two tools are published");
        check(tools.get(0).getAsJsonObject().get("name").getAsString().equals(McpServer.TOOL_INSPECT),
                "inspect first");
        check(tools.get(1).getAsJsonObject().get("name").getAsString().equals(McpServer.TOOL_PROPOSE),
                "then propose, in a fixed order");

        var inspect = tools.get(0).getAsJsonObject();
        check(inspect.get("title").getAsString().equals("Inspect Awesome TLS settings"),
                "with the locked title");
        check(inspect.get("description").getAsString().contains("never performs DNS"),
                "and the locked description");
        var annotations = inspect.getAsJsonObject("annotations");
        check(annotations.get("readOnlyHint").getAsBoolean()
                && !annotations.get("destructiveHint").getAsBoolean()
                && annotations.get("idempotentHint").getAsBoolean()
                && !annotations.get("openWorldHint").getAsBoolean(), "and the locked annotations");

        var propose = tools.get(1).getAsJsonObject();
        check(!propose.getAsJsonObject("annotations").get("readOnlyHint").getAsBoolean(),
                "propose is not marked read-only");
        check(propose.get("description").getAsString().contains("never applies settings"),
                "and says it never applies anything");

        // The published schema must be the real one, not a placeholder. This is the check that
        // catches a schema quietly degrading to {"type":"object"}.
        for (var element : tools) {
            var tool = element.getAsJsonObject();
            for (var which : List.of("inputSchema", "outputSchema")) {
                var schema = tool.getAsJsonObject(which);
                check(schema.size() > 2, tool.get("name").getAsString() + " " + which + " is substantial");
                check(!Jcs.string(schema).contains("\"$ref\":\"http"),
                        which + " has no external references a client cannot resolve");
            }
        }
        check(Jcs.string(tools.get(0).getAsJsonObject().getAsJsonObject("inputSchema"))
                        .equals(Jcs.string(McpServer.schema("inspect-input.json"))),
                "the published inspect input schema is byte-identical to the bundled one");
        check(Jcs.string(tools.get(1).getAsJsonObject().getAsJsonObject("outputSchema"))
                        .equals(Jcs.string(McpServer.schema("propose-output.json"))),
                "and so is the propose output schema");
    }

    private static void inspectRoundTrip(Fixture fixture) throws Exception {
        var arguments = "{\"schemaVersion\":\"" + Wire.SCHEMA_VERSION + "\",\"hosts\":[\"a.com\"],"
                + "\"sections\":[\"settings\",\"rules\",\"effectiveConfig\"]}";
        var result = callResult(McpServer.TOOL_INSPECT, arguments);

        check(result.get("resultType").getAsString().equals("complete"), "a tool call is complete");
        check(!result.get("isError").getAsBoolean(), "and not an error");

        var structured = result.getAsJsonObject("structuredContent");
        check(structured.get("kind").getAsString().equals("inspect_page"), "carrying an inspect page");
        check(structured.getAsJsonObject("sections").has("effectiveConfigs"),
                "with the effective config that was asked for");
        check(!structured.getAsJsonObject("sections").has("runtime"),
                "and nothing that was not");

        // The text content must be the exact serialization, not a summary of it.
        var content = result.getAsJsonArray("content");
        check(content.size() == 1, "there is exactly one content item");
        var text = content.get(0).getAsJsonObject().get("text").getAsString();
        check(text.equals(Jcs.string(structured)),
                "and its text is the structured content, verbatim and unredacted");

        // Schema version is mandatory and exact.
        var wrongVersion = callResult(McpServer.TOOL_INSPECT, "{\"schemaVersion\":\"v2\"}");
        check(wrongVersion.get("isError").getAsBoolean(), "an unknown schema version is an error");
        check(wrongVersion.getAsJsonObject("structuredContent").get("code").getAsString()
                .equals("UNSUPPORTED_SCHEMA"), "reported as an unsupported schema");

        // hosts and effectiveConfig have to be asked for together.
        var lonely = callResult(McpServer.TOOL_INSPECT, "{\"schemaVersion\":\"" + Wire.SCHEMA_VERSION
                + "\",\"sections\":[\"effectiveConfig\"]}");
        check(lonely.get("isError").getAsBoolean(), "effectiveConfig without hosts is refused");
    }

    private static void proposeRoundTrip(Fixture fixture) throws Exception {
        var revision = fixture.control.snapshot().revision();
        var arguments = "{\"schemaVersion\":\"" + Wire.SCHEMA_VERSION + "\",\"expectedRevision\":\""
                + revision + "\",\"requestId\":\"mcp-1\",\"summary\":\"raise the timeout\","
                + "\"patch\":{\"settings\":{\"httpTimeout\":45}}}";
        var result = callResult(McpServer.TOOL_PROPOSE, arguments);

        check(!result.get("isError").getAsBoolean(), "a valid proposal is not an error");
        var structured = result.getAsJsonObject("structuredContent");
        check(structured.get("status").getAsString().equals("PENDING"), "and comes back pending");
        check(structured.get("summary").getAsString().equals("raise the timeout"), "with its summary");
        check(structured.getAsJsonArray("diff").size() == 1, "and a diff");

        check(fixture.control.snapshot().revision().equals(revision),
                "proposing over MCP changes no settings");
        check(fixture.service.pending() != null, "but does park a proposal for review");

        // There is deliberately no tool that applies it.
        var listed = body(send(withMethod("tools/list", listBody())))
                .getAsJsonObject("result").getAsJsonArray("tools");
        var names = new ArrayList<String>();
        listed.forEach(t -> names.add(t.getAsJsonObject().get("name").getAsString()));
        check(names.size() == 2 && !Jcs.string(listed).contains("apply"),
                "and no tool that could apply, approve or revert one");

        var unknownTool = send(withMethod("tools/call", callBody("awesome_tls.settings.apply", "{}"))
                .header("Mcp-Name", "awesome_tls.settings.apply"));
        check(unknownTool.statusCode() == 400, "asking for one is an invalid request");
    }

    private static void businessErrorsAreResultsNotProtocolErrors(Fixture fixture) throws Exception {
        // Free the pending slot left by the previous check, so this exercises the revision guard
        // rather than the one-at-a-time guard.
        fixture.service.reject(fixture.service.pending().id(), "done with it");

        var arguments = "{\"schemaVersion\":\"" + Wire.SCHEMA_VERSION + "\",\"expectedRevision\":\""
                + "sha256:" + "0".repeat(64) + "\",\"requestId\":\"stale\","
                + "\"patch\":{\"settings\":{\"httpTimeout\":45}}}";
        var response = send(withMethod("tools/call", callBody(McpServer.TOOL_PROPOSE, arguments))
                .header("Mcp-Name", McpServer.TOOL_PROPOSE));

        check(response.statusCode() == 200, "a rejected proposal is a successful call");
        var envelope = body(response);
        check(!envelope.has("error"), "not a JSON-RPC error");
        var result = envelope.getAsJsonObject("result");
        check(result.get("isError").getAsBoolean(), "flagged as a tool error");
        var structured = result.getAsJsonObject("structuredContent");
        check(structured.get("kind").getAsString().equals("error"), "with the error envelope");
        check(structured.get("code").getAsString().equals("REVISION_CONFLICT"), "and a business code");
        check(structured.get("retryable").getAsBoolean(), "saying whether a retry could help");
        check(structured.has("currentRevision"), "and what the current revision is");
        check(result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString()
                .equals(Jcs.string(structured)), "and the text content matches it exactly");
    }

    private static void noCorsHeaders() throws Exception {
        var response = send(post(discoverBody()));
        for (var header : List.of("Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
                "Access-Control-Allow-Headers", "Access-Control-Allow-Credentials")) {
            check(response.headers().firstValue(header).isEmpty(), "no " + header + " is returned");
        }
    }

    private static void bodyTooLarge() throws Exception {
        var oversized = new byte[McpServer.MAX_BODY_BYTES + 1];
        java.util.Arrays.fill(oversized, (byte) ' ');
        oversized[0] = '{';
        oversized[oversized.length - 1] = '}';

        var response = send(base().header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", McpServer.PROTOCOL_VERSION)
                .header("Mcp-Method", "server/discover")
                .POST(HttpRequest.BodyPublishers.ofByteArray(oversized)));

        check(response.statusCode() == 413, "an oversized body is refused with 413");
        var error = errorOf(response);
        check(error.get("code").getAsInt() == McpServer.CODE_BODY_TOO_LARGE, "with the size code");
        var data = error.getAsJsonObject("data");
        check(data.get("code").getAsString().equals("BODY_TOO_LARGE"), "and its data code");
        check(data.get("maxBytes").getAsInt() == McpServer.MAX_BODY_BYTES, "naming the limit");
    }

    /**
     * The concurrency slot is taken before the body is read, so a request that has sent its headers
     * and then stopped holds one. Driven with raw sockets rather than an HTTP client, because a
     * client pools and serializes connections in ways that make "two requests at once" unreliable
     * to arrange, and the point here is the server's ceiling, not the client's scheduling.
     */
    private static void concurrencyCeiling(Fixture fixture) throws Exception {
        // Roll the rate window forward first. Everything this check has already sent counts
        // towards it, and a rate rejection would pre-empt the concurrency one being tested here.
        var clock = new StepClock();
        clock.advance(McpServer.RATE_WINDOW.multipliedBy(2));
        fixture.server.setClock(clock);

        var held = new ArrayList<java.net.Socket>();
        try {
            for (var i = 0; i < McpServer.MAX_CONCURRENT; i++) {
                held.add(openStalledRequest());
            }
            Thread.sleep(500);

            var rejected = send(post(discoverBody()));
            check(rejected.statusCode() == 429, "a request beyond the concurrency ceiling is refused");
            var error = errorOf(rejected);
            check(error.get("code").getAsInt() == McpServer.CODE_CONCURRENCY_LIMITED,
                    "with the right code");
            var data = error.getAsJsonObject("data");
            check(data.get("code").getAsString().equals("CONCURRENCY_LIMITED"), "and data code");
            check(data.get("limit").getAsInt() == McpServer.MAX_CONCURRENT, "naming the limit");
            check(data.get("retryable").getAsBoolean(), "and saying a retry is worth it");
        } finally {
            for (var socket : held) {
                socket.close();
            }
        }

        // Closing the stalled connections must give the slots back, not leak them.
        Thread.sleep(500);
        check(send(post(discoverBody())).statusCode() == 200,
                "and the slots are released when those requests end");
        fixture.server.setClock(Clock.systemUTC());
    }

    /**
     * @return a socket that has sent a complete set of request headers and then nothing, so the
     * handler is running and blocked reading the body.
     */
    private static java.net.Socket openStalledRequest() throws IOException {
        var socket = new java.net.Socket("127.0.0.1", port);
        var request = "POST " + McpServer.PATH + " HTTP/1.1\r\n"
                + "Host: 127.0.0.1:" + port + "\r\n"
                + "Content-Type: application/json\r\n"
                + "Accept: application/json, text/event-stream\r\n"
                + "MCP-Protocol-Version: " + McpServer.PROTOCOL_VERSION + "\r\n"
                + "Mcp-Method: server/discover\r\n"
                + "Transfer-Encoding: chunked\r\n"
                + "\r\n";
        socket.getOutputStream().write(request.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        socket.getOutputStream().flush();
        return socket;
    }

    private static void rateLimit(Fixture fixture) throws Exception {
        // A fresh clock, so earlier tests in this run do not count towards the window.
        var clock = new StepClock();
        fixture.server.setClock(clock);

        HttpResponse<String> limited = null;
        for (var i = 0; i < McpServer.RATE_LIMIT + 5; i++) {
            var response = send(post(discoverBody()));
            if (response.statusCode() == 429) {
                limited = response;
                break;
            }
        }
        check(limited != null, "the rate limit is reached");
        var error = errorOf(limited);
        check(error.get("code").getAsInt() == McpServer.CODE_RATE_LIMITED, "with the rate code");
        var data = error.getAsJsonObject("data");
        check(data.get("code").getAsString().equals("RATE_LIMITED"), "and its data code");
        check(data.get("limit").getAsInt() == McpServer.RATE_LIMIT, "naming the limit");
        check(data.get("windowSeconds").getAsInt() == McpServer.RATE_WINDOW.toSeconds(),
                "and the window");
        check(data.has("retryAfterMs"), "and when to try again");
        var retryAfter = limited.headers().firstValue("Retry-After");
        check(retryAfter.isPresent(), "with a Retry-After header");
        check(Integer.parseInt(retryAfter.get())
                        >= Math.ceil(data.get("retryAfterMs").getAsLong() / 1000.0) - 1,
                "that agrees with retryAfterMs");

        // Once the window rolls, requests are accepted again.
        clock.advance(McpServer.RATE_WINDOW.plusSeconds(1));
        check(send(post(discoverBody())).statusCode() == 200, "the window is rolling, not a lockout");

        fixture.server.setClock(Clock.systemUTC());
    }

    private static void restartAndBindConflict(Fixture fixture) throws Exception {
        var restartPort = freePort();
        fixture.server.start(restartPort);
        check(fixture.server.running(), "the listener restarts on a new port");
        fixture.server.stop();
        check(portIsFree(restartPort), "and releases it again");

        try (var hog = new ServerSocket(restartPort, 0, java.net.InetAddress.getByName("127.0.0.1"))) {
            try {
                fixture.server.start(restartPort);
                check(false, "a taken port must fail rather than silently move");
            } catch (IOException expected) {
                check(expected.getMessage() != null && !expected.getMessage().isBlank(),
                        "reporting the original bind error");
            }
            check(!fixture.server.running(), "and the listener stays down");
        }
    }

    // ------------------------------------------------------------------ plumbing

    private static final class Fixture {
        final SettingsControl control;
        final AiSettingsService service;
        final McpServer server;

        private Fixture(Path dir) {
            var rulesPath = dir.resolve(RuleStore.FILE_NAME);
            var audit = new AuditTrail(dir.resolve("audit"));
            var store = new RuleStore(rulesPath, s -> {
            });
            var auditOn = new AtomicBoolean(false);
            Ports.PreferencesPort preferences = new Ports.PreferencesPort() {
                private BusinessSettings settings = BusinessSettings.defaults();

                @Override
                public BusinessSettings read() {
                    return settings;
                }

                @Override
                public void write(BusinessSettings value) {
                    settings = value.normalized();
                }
            };
            Ports.RuleFilePort rules = new Ports.RuleFilePort() {
                @Override
                public RuleStore.Probe probe() {
                    return store.probe();
                }

                @Override
                public void saveIfUnchanged(String expectedDigest, List<FingerprintRule> value)
                        throws IOException {
                    store.saveIfUnchanged(expectedDigest, value);
                }

                @Override
                public Path path() {
                    return rulesPath;
                }
            };
            this.control = new SettingsControl(preferences, rules,
                    new TransactionJournal(dir.resolve(TransactionJournal.FILE_NAME)), audit,
                    auditOn::get, RuntimeStatus::unknown,
                    () -> Set.of("chrome", "firefox", "default"), Ports.UiDirtyPort.SETTLED,
                    Ports.Log.SILENT);
            this.service = new AiSettingsService(control, audit, auditOn::get, () -> true,
                    () -> false, Clock.systemUTC());
            this.server = new McpServer(service, audit, auditOn::get, () -> false, Ports.Log.SILENT, "test");
        }

        static Fixture create() throws IOException {
            var fixture = new Fixture(Files.createTempDirectory("awesome-tls-mcp"));
            fixture.control.start(null, List.of());
            fixture.control.commit(fixture.control.snapshot()
                            .withRules(List.of(new FingerprintRule("a.com", "chrome", "", "", null, true))),
                    TransactionJournal.Source.UI_SAVE);
            return fixture;
        }
    }

    /** A clock the rate-limit test can move, so a sixty-second window is testable in milliseconds. */
    private static final class StepClock extends Clock {
        private volatile java.time.Instant now = java.time.Instant.parse("2026-08-25T12:00:00Z");

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public java.time.Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    private static int freePort() throws IOException {
        try (var socket = new ServerSocket(0, 0, java.net.InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    private static boolean portIsFree(int candidate) {
        try (var socket = new ServerSocket(candidate, 0, java.net.InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort() == candidate;
        } catch (IOException e) {
            return false;
        }
    }

    private static HttpRequest.Builder base() {
        return HttpRequest.newBuilder(URI.create(base)).timeout(Duration.ofSeconds(20));
    }

    private static HttpRequest.Builder post(String body) {
        return post(HttpRequest.BodyPublishers.ofString(body));
    }

    private static HttpRequest.Builder post(HttpRequest.BodyPublisher body) {
        return base()
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", McpServer.PROTOCOL_VERSION)
                .header("Mcp-Method", "server/discover")
                .POST(body);
    }

    /**
     * The same request with a chosen {@code Mcp-Method}. Set rather than added, because
     * {@code header} appends and a repeated required header is itself a mismatch.
     */
    private static HttpRequest.Builder withMethod(String method, String body) {
        return base()
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", McpServer.PROTOCOL_VERSION)
                .header("Mcp-Method", method)
                .POST(HttpRequest.BodyPublishers.ofString(body));
    }

    private static String discoverBody() {
        return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\"}";
    }

    private static String listBody() {
        return "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}";
    }

    private static String callBody(String tool, String arguments) {
        return "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\""
                + tool + "\",\"arguments\":" + arguments + "}}";
    }

    private static JsonObject callResult(String tool, String arguments) throws Exception {
        var response = send(withMethod("tools/call", callBody(tool, arguments)).header("Mcp-Name", tool));
        check(response.statusCode() == 200, "a tool call returns 200");
        return body(response).getAsJsonObject("result");
    }

    private static HttpResponse<String> send(HttpRequest.Builder builder) throws Exception {
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static JsonObject body(HttpResponse<String> response) {
        return JsonParser.parseString(response.body()).getAsJsonObject();
    }

    private static JsonObject errorOf(HttpResponse<String> response) {
        return body(response).getAsJsonObject("error");
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
