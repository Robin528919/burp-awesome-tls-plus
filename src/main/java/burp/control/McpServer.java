package burp.control;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.eclipse.jetty.io.Content;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The local MCP endpoint.
 * <p>
 * Bound to the literal address {@code 127.0.0.1} and nothing else, POST-only, and with no
 * authentication of any kind. ADR-0001 section 4.2 accepts that last part as a disclosed risk
 * rather than papering over it: any process on this machine that can open a socket to the port can
 * read the full settings, credentials included, and can submit a proposal. What it cannot do is
 * apply one. The loopback bind, the exact-{@code Host} check and the blanket {@code Origin}
 * rejection are hardening against a browser or a misrouted request wandering in; none of them is
 * authentication and the UI never calls them that.
 * <p>
 * Everything here is transport. Business failures — a stale revision, a rejected patch — come back
 * as a successful JSON-RPC result carrying an error payload, because a refused proposal is the tool
 * working correctly. Only malformed protocol, a failed gate or a limit produces a JSON-RPC error.
 */
public final class McpServer {
    public static final String PROTOCOL_VERSION = "2026-07-28";
    public static final String PATH = "/mcp";
    public static final String BIND_HOST = "127.0.0.1";
    public static final int DEFAULT_PORT = 8885;

    /** Section 5 limits. Global, because there is no trustworthy client identity to bucket by. */
    public static final int MAX_BODY_BYTES = 16 * 1024 * 1024;
    public static final int RATE_LIMIT = 30;
    public static final Duration RATE_WINDOW = Duration.ofSeconds(60);
    public static final int MAX_CONCURRENT = 2;

    // Project transport codes. Section 15 puts these in the unreserved -31900..-31906 range, well
    // clear of both the JSON-RPC reserved block and MCP's own -32020..-32099.
    static final int CODE_GATE_REJECTED = -31900;
    static final int CODE_UNSUPPORTED_MEDIA_TYPE = -31901;
    static final int CODE_NOT_ACCEPTABLE = -31902;
    static final int CODE_BODY_TOO_LARGE = -31903;
    static final int CODE_RATE_LIMITED = -31904;
    static final int CODE_CONCURRENCY_LIMITED = -31905;
    static final int CODE_UNSUPPORTED_NOTIFICATION = -31906;

    static final int CODE_PARSE_ERROR = -32700;
    static final int CODE_INVALID_REQUEST = -32600;
    static final int CODE_METHOD_NOT_FOUND = -32601;
    static final int CODE_INVALID_PARAMS = -32602;
    static final int CODE_HEADER_MISMATCH = -32020;
    static final int CODE_UNSUPPORTED_PROTOCOL_VERSION = -32022;

    public static final String TOOL_INSPECT = "awesome_tls.settings.inspect";
    public static final String TOOL_PROPOSE = "awesome_tls.settings.propose";

    private final AiSettingsService service;
    private final AuditTrail audit;
    private final java.util.function.BooleanSupplier auditEnabled;
    private final Ports.Log log;
    private final String extensionVersion;

    private final AtomicReference<Server> server = new AtomicReference<>();
    private final AtomicReference<String> boundEndpoint = new AtomicReference<>();
    private final AtomicInteger inFlight = new AtomicInteger();
    private final ArrayDeque<Instant> recentRequests = new ArrayDeque<>();
    private final Object rateLock = new Object();
    private volatile int port = DEFAULT_PORT;
    private volatile java.time.Clock clock = java.time.Clock.systemUTC();

    public McpServer(AiSettingsService service, AuditTrail audit,
                     java.util.function.BooleanSupplier auditEnabled, Ports.Log log,
                     String extensionVersion) {
        this.service = service;
        this.audit = audit;
        this.auditEnabled = auditEnabled;
        this.log = log;
        this.extensionVersion = extensionVersion;
    }

    /**
     * Test seam: a sixty-second rate window is otherwise not exercisable in reasonable time.
     * <p>
     * Swapping the clock also drops the window, because timestamps taken from one timeline cannot
     * be compared against another.
     */
    void setClock(java.time.Clock clock) {
        synchronized (rateLock) {
            recentRequests.clear();
        }
        this.clock = clock;
    }

    public boolean running() {
        return server.get() != null;
    }

    public String endpoint() {
        return boundEndpoint.get();
    }

    public int port() {
        return port;
    }

    /**
     * Starts the listener.
     * <p>
     * A port that is already taken is a hard failure. Section 4.1 forbids falling back to another
     * port: a client is configured with a fixed endpoint, and silently moving would leave it
     * talking to whatever else is on the original one.
     *
     * @throws IOException if the port cannot be bound. The message is the original one, because it
     *                     is the only thing that tells the user what else has the port.
     */
    public void start(int requestedPort) throws IOException {
        synchronized (this) {
            if (server.get() != null) {
                return;
            }
            this.port = requestedPort;

            // Full audit is fail-closed, so the attempt is recorded before anything is listening.
            if (auditEnabled.getAsBoolean()) {
                var body = new JsonObject();
                body.addProperty("endpoint", "http://" + BIND_HOST + ":" + requestedPort + PATH);
                audit.append("LISTENER_ENABLE_ATTEMPT", body);
            }

            // Jetty needs acceptor, selector and worker threads; starving the pool deadlocks it.
            // The two-request ceiling of section 5 is enforced in the handler, not here.
            var pool = new QueuedThreadPool(16, 4, 30_000);
            pool.setName("awesome-tls-mcp");
            pool.setDaemon(true);

            var jetty = new Server(pool);
            var connector = new ServerConnector(jetty);
            connector.setHost(BIND_HOST);
            connector.setPort(requestedPort);
            jetty.addConnector(connector);
            jetty.setHandler(new McpHandler());

            try {
                jetty.start();
            } catch (Exception e) {
                try {
                    jetty.stop();
                } catch (Exception ignored) {
                    // Already failing; the original cause is what matters.
                }
                throw new IOException(rootMessage(e), e);
            }

            server.set(jetty);
            boundEndpoint.set("http://" + BIND_HOST + ":" + connector.getLocalPort() + PATH);
            this.port = connector.getLocalPort();
            log.info("AI Control listening on " + boundEndpoint.get());

            if (auditEnabled.getAsBoolean()) {
                var body = new JsonObject();
                body.addProperty("endpoint", boundEndpoint.get());
                audit.append("LISTENER_STARTED", body);
            }
        }
    }

    /**
     * Stops the listener and drops everything belonging to the session.
     * <p>
     * Shutting down takes priority over recording it. Section 14.2 is explicit that a failing audit
     * append must never keep the endpoint open: an unlogged shutdown is a reporting problem, and a
     * listener that stays up because it could not write a log line is a security problem.
     */
    public void stop() {
        synchronized (this) {
            var jetty = server.getAndSet(null);
            boundEndpoint.set(null);
            if (jetty != null) {
                try {
                    jetty.stop();
                    jetty.destroy();
                } catch (Exception e) {
                    log.error("Could not stop the AI Control listener cleanly: " + e);
                }
            }

            service.clearSession();
            synchronized (rateLock) {
                recentRequests.clear();
            }
            inFlight.set(0);

            if (jetty != null && auditEnabled.getAsBoolean()) {
                try {
                    audit.append("LISTENER_STOPPED", new JsonObject());
                } catch (IOException e) {
                    log.error("The AI Control listener was stopped but this could not be recorded: " + e);
                }
            }
        }
    }

    private static String rootMessage(Throwable e) {
        var cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage() == null ? cause.toString() : cause.getMessage();
    }

    // ------------------------------------------------------------------ handler

    private final class McpHandler extends Handler.Abstract {
        @Override
        public boolean handle(Request request, Response response, Callback callback) {
            try {
                dispatch(request, response, callback);
            } catch (Throwable e) {
                // Never let an internal fault escape as a stack trace to the client.
                log.error("AI Control request failed: " + e);
                write(response, callback, 500, jsonRpcError(null, CODE_INVALID_REQUEST,
                        "internal error", null));
            }
            return true;
        }
    }

    private void dispatch(Request request, Response response, Callback callback) {
        if (!PATH.equals(request.getHttpURI().getPath())) {
            write(response, callback, 404, jsonRpcError(null, CODE_METHOD_NOT_FOUND, "not found", null));
            return;
        }
        if (!"POST".equals(request.getMethod())) {
            // No standalone stream, no protocol session: section 16.1 refuses GET and DELETE.
            response.getHeaders().put("Allow", "POST");
            write(response, callback, 405, jsonRpcError(null, CODE_INVALID_REQUEST,
                    "only POST is supported", null));
            return;
        }

        // ---- gate 1: exactly one Host, exactly the configured one.
        var hosts = request.getHeaders().getValuesList("Host");
        if (hosts.size() != 1 || !hosts.get(0).equals(BIND_HOST + ":" + port)) {
            reject("HOST_REJECTED", hosts.size(), null);
            write(response, callback, 403, gateError("HOST_REJECTED"));
            return;
        }

        // ---- gate 2: any Origin at all is refused. The value is not even compared, because the
        // only clients this endpoint supports never send one, and comparing invites an allowlist.
        if (!request.getHeaders().getValuesList("Origin").isEmpty()) {
            reject("ORIGIN_REJECTED", 0, null);
            write(response, callback, 403, gateError("ORIGIN_REJECTED"));
            return;
        }

        // ---- gate 3: framing.
        var contentType = single(request, "Content-Type");
        if (contentType == null || !isJsonContentType(contentType)) {
            write(response, callback, 415, dataError(CODE_UNSUPPORTED_MEDIA_TYPE,
                    "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json"));
            return;
        }
        var encoding = single(request, "Content-Encoding");
        if (encoding != null && !encoding.trim().equalsIgnoreCase("identity")) {
            write(response, callback, 415, dataError(CODE_UNSUPPORTED_MEDIA_TYPE,
                    "UNSUPPORTED_MEDIA_TYPE", "Content-Encoding must be identity"));
            return;
        }
        if (!acceptsBoth(request)) {
            write(response, callback, 406, dataError(CODE_NOT_ACCEPTABLE, "NOT_ACCEPTABLE",
                    "Accept must include both application/json and text/event-stream"));
            return;
        }
        var declared = request.getHeaders().getLongField("Content-Length");
        if (declared > MAX_BODY_BYTES) {
            write(response, callback, 413, bodyTooLarge(declared));
            return;
        }

        // ---- gate 4: rate. Every attempt that got this far counts, including ones about to be
        // rejected for their contents; otherwise a stream of malformed requests is free.
        if (!allowByRate()) {
            var retryAfterMs = retryAfterMillis();
            response.getHeaders().put("Retry-After",
                    String.valueOf((retryAfterMs + 999) / 1000));
            write(response, callback, 429, rateLimited(retryAfterMs));
            return;
        }

        // ---- gate 5: concurrency, taken before the body is read so a large body cannot occupy
        // memory while waiting.
        if (inFlight.incrementAndGet() > MAX_CONCURRENT) {
            inFlight.decrementAndGet();
            write(response, callback, 429, concurrencyLimited());
            return;
        }

        try {
            byte[] body;
            try {
                body = readBody(request);
            } catch (BodyTooLargeException e) {
                write(response, callback, 413, bodyTooLarge(e.observed));
                return;
            } catch (IOException e) {
                write(response, callback, 400, jsonRpcError(null, CODE_PARSE_ERROR,
                        "could not read the request body", null));
                return;
            }

            handleBody(request, response, callback, body);
        } finally {
            inFlight.decrementAndGet();
        }
    }

    private void handleBody(Request request, Response response, Callback callback, byte[] body) {
        JsonObject envelope;
        try {
            var parsed = JsonParser.parseString(new String(body, StandardCharsets.UTF_8));
            if (!parsed.isJsonObject()) {
                write(response, callback, 400, jsonRpcError(null, CODE_INVALID_REQUEST,
                        "the request must be a JSON-RPC object", null));
                return;
            }
            envelope = parsed.getAsJsonObject();
        } catch (JsonSyntaxException e) {
            write(response, callback, 400, jsonRpcError(null, CODE_PARSE_ERROR, "invalid JSON", null));
            return;
        }

        var protocolVersion = single(request, "MCP-Protocol-Version");
        if (!PROTOCOL_VERSION.equals(protocolVersion)) {
            var data = new JsonObject();
            data.addProperty("requested", protocolVersion == null ? "" : protocolVersion);
            data.add("supported", Wire.strings(List.of(PROTOCOL_VERSION)));
            write(response, callback, 400, jsonRpcError(null, CODE_UNSUPPORTED_PROTOCOL_VERSION,
                    "unsupported protocol version", data));
            return;
        }

        if (!envelope.has("jsonrpc") || !"2.0".equals(asString(envelope.get("jsonrpc")))) {
            write(response, callback, 400, jsonRpcError(idOf(envelope), CODE_INVALID_REQUEST,
                    "jsonrpc must be \"2.0\"", null));
            return;
        }
        var method = asString(envelope.get("method"));
        if (method == null || method.isEmpty()) {
            write(response, callback, 400, jsonRpcError(idOf(envelope), CODE_INVALID_REQUEST,
                    "method is required", null));
            return;
        }

        // A request without an id is a notification. Streamable HTTP defines no client-to-server
        // notification in this protocol version, so it is refused without changing any state and
        // without echoing an id that does not exist.
        if (!envelope.has("id") || envelope.get("id").isJsonNull()) {
            reject("UNSUPPORTED_NOTIFICATION", 0, method);
            write(response, callback, 400, dataError(CODE_UNSUPPORTED_NOTIFICATION,
                    "UNSUPPORTED_NOTIFICATION", "notifications are not supported"));
            return;
        }
        var id = envelope.get("id");

        // ---- header/body agreement. Checked before method dispatch, so a mismatched header on an
        // unimplemented method is still a mismatch rather than a 404.
        var mcpMethod = single(request, "Mcp-Method");
        if (mcpMethod == null || !mcpMethod.equals(method)) {
            write(response, callback, 400, jsonRpcError(id, CODE_HEADER_MISMATCH,
                    "Mcp-Method must match the request method", null));
            return;
        }
        var nameMismatch = checkMcpName(request, method, envelope);
        if (nameMismatch != null) {
            write(response, callback, 400, jsonRpcError(id, CODE_HEADER_MISMATCH, nameMismatch, null));
            return;
        }

        switch (method) {
            case "server/discover" -> write(response, callback, 200, jsonRpcResult(id, discover()));
            case "tools/list" -> write(response, callback, 200, jsonRpcResult(id, toolsList()));
            case "tools/call" -> callTool(response, callback, id, envelope);
            default -> write(response, callback, 404, jsonRpcError(id, CODE_METHOD_NOT_FOUND,
                    "unknown method \"" + method + "\"", null));
        }
    }

    /**
     * The official header contract binds {@code Mcp-Name} to a body field for three methods. Two of
     * them are not implemented here, but the header is still validated before the method-not-found
     * answer, so a client's mistake is reported as the mismatch it is.
     *
     * @return null when acceptable, otherwise the message to return with {@code -32020}.
     */
    private String checkMcpName(Request request, String method, JsonObject envelope) {
        String bodyField = switch (method) {
            case "tools/call", "prompts/get" -> "name";
            case "resources/read" -> "uri";
            default -> null;
        };
        if (bodyField == null) {
            return null;
        }

        var header = single(request, "Mcp-Name");
        if (header == null) {
            return "Mcp-Name is required for " + method;
        }
        String decoded;
        try {
            decoded = decodeHeaderSentinel(header);
        } catch (IllegalArgumentException e) {
            return "Mcp-Name is not a valid encoded header value";
        }

        var params = envelope.has("params") && envelope.get("params").isJsonObject()
                ? envelope.getAsJsonObject("params") : null;
        var expected = params == null ? null : asString(params.get(bodyField));
        if (expected == null || !expected.equals(decoded)) {
            return "Mcp-Name must match params." + bodyField;
        }
        return null;
    }

    /**
     * Decodes the {@code =?base64?...?=} sentinel MCP uses for header values that are not plain
     * ASCII. Plain values pass through; a malformed encoding is refused rather than compared
     * literally, because comparing it literally would let a mangled name match nothing and produce
     * a confusing method-not-found instead of a header error.
     */
    static String decodeHeaderSentinel(String value) {
        if (!value.startsWith("=?") || !value.endsWith("?=") || value.length() < 5) {
            return value;
        }
        var inner = value.substring(2, value.length() - 2);
        // Both the bare "base64?<data>" form and the RFC 2047 "utf-8?B?<data>" spelling.
        var marker = inner.toLowerCase(Locale.ROOT);
        String data;
        if (marker.startsWith("base64?")) {
            data = inner.substring("base64?".length());
        } else {
            var parts = inner.split("\\?", 3);
            if (parts.length != 3 || !parts[1].equalsIgnoreCase("B")) {
                throw new IllegalArgumentException("unsupported header encoding");
            }
            data = parts[2];
        }
        return new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ methods

    JsonObject discover() {
        var result = new JsonObject();
        result.addProperty("resultType", "complete");
        result.add("supportedVersions", Wire.strings(List.of(PROTOCOL_VERSION)));

        var capabilities = new JsonObject();
        var tools = new JsonObject();
        tools.addProperty("listChanged", false);
        capabilities.add("tools", tools);
        result.add("capabilities", capabilities);

        var meta = new JsonObject();
        var serverInfo = new JsonObject();
        serverInfo.addProperty("name", "burp-awesome-tls-plus");
        serverInfo.addProperty("version", extensionVersion);
        meta.add("io.modelcontextprotocol/serverInfo", serverInfo);
        result.add("_meta", meta);

        result.addProperty("instructions", "Inspect settings or submit a proposal. Applying, "
                + "rejecting, and reverting are available only in the Burp AI Control tab.");
        result.addProperty("ttlMs", 0);
        result.addProperty("cacheScope", "private");
        return result;
    }

    JsonObject toolsList() {
        var result = new JsonObject();
        result.addProperty("resultType", "complete");

        var tools = new JsonArray();
        tools.add(tool(TOOL_INSPECT, "Inspect Awesome TLS settings",
                "Returns committed Awesome TLS business settings, valid domain rules, fingerprint "
                        + "catalog, runtime/proposal state, and optional effective host configuration. "
                        + "Values are unredacted; it never performs DNS or target network traffic.",
                "inspect-input.json", "inspect-output.json", true, true));
        tools.add(tool(TOOL_PROPOSE, "Propose Awesome TLS settings changes",
                "Validates and records one settings proposal for review in Burp. It never applies "
                        + "settings; approval, rejection, and revert remain local Burp UI actions.",
                "propose-input.json", "propose-output.json", false, true));
        result.add("tools", tools);

        result.addProperty("ttlMs", 0);
        result.addProperty("cacheScope", "private");
        // No nextCursor: the list is two entries and never grows within a session.
        return result;
    }

    private JsonObject tool(String name, String title, String description, String inputSchema,
                            String outputSchema, boolean readOnly, boolean idempotent) {
        var tool = new JsonObject();
        tool.addProperty("name", name);
        tool.addProperty("title", title);
        tool.addProperty("description", description);
        tool.add("inputSchema", schema(inputSchema));
        tool.add("outputSchema", schema(outputSchema));

        var annotations = new JsonObject();
        annotations.addProperty("readOnlyHint", readOnly);
        annotations.addProperty("destructiveHint", false);
        annotations.addProperty("idempotentHint", idempotent);
        annotations.addProperty("openWorldHint", false);
        tool.add("annotations", annotations);
        return tool;
    }

    /**
     * Schemas ship in the jar so what is published and what is enforced cannot drift apart.
     */
    static JsonObject schema(String resource) {
        try (var stream = McpServer.class.getResourceAsStream("/mcp/" + resource)) {
            if (stream == null) {
                throw new IllegalStateException("missing bundled schema /mcp/" + resource);
            }
            return JsonParser.parseString(new String(stream.readAllBytes(), StandardCharsets.UTF_8))
                    .getAsJsonObject();
        } catch (IOException e) {
            throw new IllegalStateException("could not read bundled schema /mcp/" + resource, e);
        }
    }

    private void callTool(Response response, Callback callback, JsonElement id, JsonObject envelope) {
        if (!envelope.has("params") || !envelope.get("params").isJsonObject()) {
            write(response, callback, 400, jsonRpcError(id, CODE_INVALID_PARAMS,
                    "params must be an object", null));
            return;
        }
        var params = envelope.getAsJsonObject("params");
        var name = asString(params.get("name"));
        if (name == null) {
            write(response, callback, 400, jsonRpcError(id, CODE_INVALID_PARAMS,
                    "params.name is required", null));
            return;
        }
        var arguments = params.has("arguments") && params.get("arguments").isJsonObject()
                ? params.getAsJsonObject("arguments") : new JsonObject();

        JsonObject payload;
        switch (name) {
            case TOOL_INSPECT -> payload = inspect(arguments);
            case TOOL_PROPOSE -> payload = propose(arguments);
            default -> {
                write(response, callback, 400, jsonRpcError(id, CODE_INVALID_PARAMS,
                        "unknown tool \"" + name + "\"", null));
                return;
            }
        }
        write(response, callback, 200, jsonRpcResult(id, callToolResult(payload)));
    }

    private JsonObject inspect(JsonObject arguments) {
        var badSchema = requireSchemaVersion(arguments);
        if (badSchema != null) {
            return badSchema;
        }
        if (arguments.has("cursor")) {
            // Chunking is only reachable through a cursor this session issued, and v1 never issues
            // one: every value the two tools return fits comfortably inside a single page.
            return Wire.error(Wire.Code.CURSOR_INVALID, "That cursor was not issued by this session.",
                    List.of(Wire.ErrorDetail.of("/cursor", "unknown_cursor")), null);
        }

        List<String> sections = null;
        if (arguments.has("sections")) {
            sections = new java.util.ArrayList<>();
            for (var element : arguments.getAsJsonArray("sections")) {
                sections.add(element.getAsString());
            }
        }
        List<String> hosts = null;
        if (arguments.has("hosts")) {
            hosts = new java.util.ArrayList<>();
            for (var element : arguments.getAsJsonArray("hosts")) {
                hosts.add(asString(element));
            }
        }
        if (sections != null && sections.contains("effectiveConfig") && hosts == null) {
            return Wire.error(Wire.Code.VALIDATION_FAILED,
                    "Asking for effectiveConfig requires a list of hosts.",
                    List.of(Wire.ErrorDetail.of("/hosts", "required_for_effective_config")), null);
        }
        if (hosts != null && sections != null && !sections.contains("effectiveConfig")) {
            return Wire.error(Wire.Code.VALIDATION_FAILED,
                    "Hosts were given but effectiveConfig was not requested.",
                    List.of(Wire.ErrorDetail.of("/sections", "missing_effective_config")), null);
        }
        return service.inspect(sections, hosts);
    }

    private JsonObject propose(JsonObject arguments) {
        var badSchema = requireSchemaVersion(arguments);
        if (badSchema != null) {
            return badSchema;
        }
        for (var key : arguments.keySet()) {
            if (!List.of("schemaVersion", "expectedRevision", "requestId", "summary",
                    "acknowledgements", "patch").contains(key)) {
                return Wire.error(Wire.Code.UNSUPPORTED_SCHEMA,
                        "Unknown argument \"" + key + "\".",
                        List.of(Wire.ErrorDetail.of("/" + Validation.escapeToken(key), "unknown_field")), null);
            }
        }

        var expectedRevision = asString(arguments.get("expectedRevision"));
        if (expectedRevision == null || !Jcs.isDigest(expectedRevision)) {
            return Wire.error(Wire.Code.VALIDATION_FAILED, "expectedRevision must be a settings revision.",
                    List.of(Wire.ErrorDetail.of("/expectedRevision", "not_a_revision")), null);
        }
        var requestId = asString(arguments.get("requestId"));
        if (requestId == null || requestId.isEmpty() || requestId.length() > 128
                || !requestId.matches("^[A-Za-z0-9._:-]+$")) {
            return Wire.error(Wire.Code.VALIDATION_FAILED, "requestId is missing or malformed.",
                    List.of(Wire.ErrorDetail.of("/requestId", "malformed")), null);
        }
        if (!arguments.has("patch") || !arguments.get("patch").isJsonObject()) {
            return Wire.error(Wire.Code.VALIDATION_FAILED, "patch is required.",
                    List.of(Wire.ErrorDetail.of("/patch", "required")), null);
        }
        var summary = arguments.has("summary") ? asString(arguments.get("summary")) : "";
        if (summary != null && summary.length() > 500) {
            return Wire.error(Wire.Code.VALIDATION_FAILED, "summary is longer than 500 characters.",
                    List.of(Wire.ErrorDetail.of("/summary", "too_long")), null);
        }
        var acknowledgements = new java.util.ArrayList<String>();
        if (arguments.has("acknowledgements")) {
            if (!arguments.get("acknowledgements").isJsonArray()) {
                return Wire.error(Wire.Code.VALIDATION_FAILED, "acknowledgements must be an array.",
                        List.of(Wire.ErrorDetail.of("/acknowledgements", "not_an_array")), null);
            }
            for (var element : arguments.getAsJsonArray("acknowledgements")) {
                acknowledgements.add(asString(element));
            }
        }

        return service.propose(expectedRevision, requestId, arguments.getAsJsonObject("patch"),
                acknowledgements, summary == null ? "" : summary, arguments);
    }

    private static JsonObject requireSchemaVersion(JsonObject arguments) {
        var version = asString(arguments.get("schemaVersion"));
        if (!Wire.SCHEMA_VERSION.equals(version)) {
            return Wire.error(Wire.Code.UNSUPPORTED_SCHEMA,
                    "schemaVersion must be \"" + Wire.SCHEMA_VERSION + "\".",
                    List.of(Wire.ErrorDetail.mismatch("/schemaVersion", "unsupported_schema_version",
                            Wire.SCHEMA_VERSION, version)), null);
        }
        return null;
    }

    /**
     * Wraps a business payload as a {@code CallToolResult}: one text content carrying the exact
     * JSON serialization of {@code structuredContent}, so a client that cannot read structured
     * output still sees the same thing rather than a summary of it.
     */
    static JsonObject callToolResult(JsonObject payload) {
        var isError = payload.has("kind") && "error".equals(asString(payload.get("kind")));

        var text = new JsonObject();
        text.addProperty("type", "text");
        text.addProperty("text", Jcs.string(payload));
        var content = new JsonArray();
        content.add(text);

        var result = new JsonObject();
        result.addProperty("resultType", "complete");
        result.add("content", content);
        result.add("structuredContent", payload);
        result.addProperty("isError", isError);
        return result;
    }

    // ------------------------------------------------------------------ limits

    private boolean allowByRate() {
        var now = clock.instant();
        synchronized (rateLock) {
            while (!recentRequests.isEmpty() && recentRequests.peekFirst().isBefore(now.minus(RATE_WINDOW))) {
                recentRequests.pollFirst();
            }
            if (recentRequests.size() >= RATE_LIMIT) {
                return false;
            }
            recentRequests.addLast(now);
            return true;
        }
    }

    private long retryAfterMillis() {
        synchronized (rateLock) {
            if (recentRequests.isEmpty()) {
                return 0;
            }
            var freeAt = recentRequests.peekFirst().plus(RATE_WINDOW);
            var millis = Duration.between(clock.instant(), freeAt).toMillis();
            return Math.max(0, millis);
        }
    }

    private static final class BodyTooLargeException extends IOException {
        final long observed;

        BodyTooLargeException(long observed) {
            super("body too large");
            this.observed = observed;
        }
    }

    /**
     * Reads at most {@link #MAX_BODY_BYTES}, enforced while streaming rather than only from the
     * declared length, so a chunked request without a {@code Content-Length} cannot get around it.
     */
    private static byte[] readBody(Request request) throws IOException {
        try (InputStream stream = Content.Source.asInputStream(request)) {
            var out = new java.io.ByteArrayOutputStream();
            var buffer = new byte[8192];
            var total = 0L;
            int read;
            while ((read = stream.read(buffer)) >= 0) {
                total += read;
                if (total > MAX_BODY_BYTES) {
                    throw new BodyTooLargeException(total);
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    // ------------------------------------------------------------------ headers

    /**
     * @return the single value of {@code name}, or null when it is missing or repeated. A required
     * MCP header must have exactly one logical value; two is a mismatch, not a choice.
     */
    private static String single(Request request, String name) {
        var values = request.getHeaders().getValuesList(name);
        return values.size() == 1 ? values.get(0) : null;
    }

    private static boolean isJsonContentType(String value) {
        var media = value.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return media.equals("application/json");
    }

    /**
     * The transport requires the client to be ready for either shape, even though v1 always answers
     * with JSON.
     */
    private static boolean acceptsBoth(Request request) {
        var joined = String.join(",", request.getHeaders().getValuesList("Accept"))
                .toLowerCase(Locale.ROOT);
        return joined.contains("application/json") && joined.contains("text/event-stream");
    }

    // ------------------------------------------------------------------ responses

    private static JsonElement idOf(JsonObject envelope) {
        var id = envelope.get("id");
        return id == null || id.isJsonNull() ? null : id;
    }

    private static String asString(JsonElement element) {
        if (element == null || element.isJsonNull() || !element.isJsonPrimitive()) {
            return null;
        }
        var primitive = element.getAsJsonPrimitive();
        return primitive.isString() ? primitive.getAsString() : null;
    }

    static JsonObject jsonRpcResult(JsonElement id, JsonObject result) {
        var envelope = new JsonObject();
        envelope.addProperty("jsonrpc", "2.0");
        envelope.add("id", id);
        envelope.add("result", result);
        return envelope;
    }

    /**
     * @param id null when the request could not be associated with one. The field is then omitted
     *           rather than sent as null, because a null id is a different thing from no id.
     */
    static JsonObject jsonRpcError(JsonElement id, int code, String message, JsonObject data) {
        var error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        if (data != null) {
            error.add("data", data);
        }
        var envelope = new JsonObject();
        envelope.addProperty("jsonrpc", "2.0");
        if (id != null) {
            envelope.add("id", id);
        }
        envelope.add("error", error);
        return envelope;
    }

    private static JsonObject gateError(String code) {
        return dataError(CODE_GATE_REJECTED, code, code.equals("HOST_REJECTED")
                ? "unexpected Host header" : "Origin is not accepted");
    }

    private static JsonObject dataError(int code, String dataCode, String message) {
        var data = new JsonObject();
        data.addProperty("code", dataCode);
        return jsonRpcError(null, code, message, data);
    }

    private static JsonObject bodyTooLarge(long observed) {
        var data = new JsonObject();
        data.addProperty("code", "BODY_TOO_LARGE");
        data.addProperty("maxBytes", MAX_BODY_BYTES);
        if (observed > 0) {
            data.addProperty("observedBytes", observed);
        }
        return jsonRpcError(null, CODE_BODY_TOO_LARGE, "request body too large", data);
    }

    private JsonObject rateLimited(long retryAfterMs) {
        var data = new JsonObject();
        data.addProperty("code", "RATE_LIMITED");
        data.addProperty("limit", RATE_LIMIT);
        data.addProperty("windowSeconds", RATE_WINDOW.toSeconds());
        data.addProperty("retryAfterMs", retryAfterMs);
        return jsonRpcError(null, CODE_RATE_LIMITED, "too many requests", data);
    }

    private static JsonObject concurrencyLimited() {
        var data = new JsonObject();
        data.addProperty("code", "CONCURRENCY_LIMITED");
        data.addProperty("limit", MAX_CONCURRENT);
        data.addProperty("retryable", true);
        return jsonRpcError(null, CODE_CONCURRENCY_LIMITED, "too many concurrent requests", data);
    }

    private static void write(Response response, Callback callback, int status, JsonObject body) {
        response.setStatus(status);
        response.getHeaders().put("Content-Type", "application/json");
        // No permissive CORS headers: this endpoint is not for browsers.
        response.write(true, ByteBuffer.wrap(Jcs.bytes(body)), callback);
    }

    /**
     * Records a rejected request as metadata only.
     * <p>
     * Section 14.1 is deliberate about this: a payload that failed a gate is not a settings
     * operation, and storing it in full would mean writing whatever an unauthenticated local
     * process sent into a file the UI displays.
     */
    private void reject(String reason, int headerCount, String method) {
        if (!auditEnabled.getAsBoolean()) {
            return;
        }
        try {
            var body = new JsonObject();
            body.addProperty("reason", reason);
            if (headerCount > 0) {
                body.addProperty("headerCount", headerCount);
            }
            if (method != null) {
                body.addProperty("method", method);
            }
            audit.append("MCP_REJECTED", body);
        } catch (IOException e) {
            log.error("Could not record a rejected AI Control request: " + e);
        }
    }
}
