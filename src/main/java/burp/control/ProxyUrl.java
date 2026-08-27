package burp.control;

import java.util.Locale;
import java.util.Set;

/**
 * Decides whether an external proxy URL is one the Go side can actually dial.
 * <p>
 * ADR-0001 section 7 pins the v1 syntax to what the currently vendored
 * {@code bogdanfinn/tls-client} does: {@code url.Parse} must succeed, the host must be non-empty,
 * and the scheme must be one of six. That is narrower than "looks like a URL" and wider than
 * {@link java.net.URI} — Go accepts {@code http://h:} and an out-of-range port, and rejects a bare
 * {@code host:port} — so this reimplements Go's parser rather than delegating to a Java one that
 * disagrees at the edges. Disagreeing means either refusing a proxy that works or accepting one
 * that fails at request time, with the settings already committed.
 * <p>
 * Validation only parses. It never resolves DNS and never connects, because inspect and propose
 * are required to produce no target-side traffic. The stored value is never rewritten beyond a
 * trim; canonicalizing it here would silently change what the user typed.
 * <p>
 * The golden table in {@link #main} is generated from the vendored dialer; see
 * {@code src-go/server/proxyurl_test.go}, which asserts the same table on the Go side so a
 * dependency bump cannot widen or narrow the contract unnoticed.
 */
public final class ProxyUrl {
    /** The schemes tls-client's {@code newConnectDialer} switch actually handles. */
    static final Set<String> SUPPORTED_SCHEMES =
            Set.of("http", "https", "socks4", "socks4a", "socks5", "socks5h");

    private ProxyUrl() {
    }

    /**
     * @return null if {@code raw} is acceptable (including empty, meaning direct/inherit), or a
     * human-readable reason it is not.
     */
    public static String problem(String raw) {
        var value = raw == null ? "" : raw.trim();
        if (value.isEmpty()) {
            return null;
        }
        if (value.length() > 4096) {
            return "is unreasonably long";
        }

        Parsed parsed;
        try {
            parsed = parse(value);
        } catch (ParseException e) {
            return e.getMessage();
        }

        if (parsed.host.isEmpty()) {
            return "must include a host, for example http://user:pass@127.0.0.1:8080";
        }
        if (!SUPPORTED_SCHEMES.contains(parsed.scheme)) {
            var named = parsed.scheme.isEmpty() ? "no scheme" : "scheme \"" + parsed.scheme + "\"";
            return "has " + named + "; use http, https, socks4, socks4a, socks5 or socks5h";
        }
        return null;
    }

    public static boolean isValid(String raw) {
        return problem(raw) == null;
    }

    private record Parsed(String scheme, String host) {
    }

    private static final class ParseException extends Exception {
        ParseException(String message) {
            super(message);
        }
    }

    /**
     * A port-for-port transliteration of the parts of Go's {@code net/url.Parse} that decide
     * whether tls-client will accept a value. Anything Go's parser does not look at — path,
     * query, fragment — is discarded rather than modelled.
     */
    private static Parsed parse(String raw) throws ParseException {
        var input = raw;

        // Go strips the fragment before anything else.
        var hash = input.indexOf('#');
        if (hash >= 0) {
            input = input.substring(0, hash);
        }

        var scheme = "";
        var rest = input;

        // getScheme
        for (var i = 0; i < input.length(); i++) {
            var c = input.charAt(i);
            if (isAlpha(c)) {
                continue;
            }
            if (isDigit(c) || c == '+' || c == '-' || c == '.') {
                if (i == 0) {
                    break; // a scheme cannot start with these; there is no scheme at all
                }
                continue;
            }
            if (c == ':') {
                if (i == 0) {
                    throw new ParseException("is missing a protocol scheme");
                }
                scheme = input.substring(0, i).toLowerCase(Locale.ROOT);
                rest = input.substring(i + 1);
            }
            break;
        }

        // The query is cut before the authority, so "http://h:1?q" still has authority "h:1".
        if (rest.endsWith("?") && !rest.substring(0, rest.length() - 1).contains("?")) {
            rest = rest.substring(0, rest.length() - 1);
        } else {
            var question = rest.indexOf('?');
            if (question >= 0) {
                rest = rest.substring(0, question);
            }
        }

        if (!rest.startsWith("/")) {
            if (!scheme.isEmpty()) {
                // Opaque form such as "mailto:x": Go leaves Host empty, so this is unusable.
                return new Parsed(scheme, "");
            }
            var slash = rest.indexOf('/');
            var segment = slash < 0 ? rest : rest.substring(0, slash);
            if (segment.contains(":")) {
                // Go's guard against "cache_object:foo/bar"; it is also what rejects a bare
                // "127.0.0.1:8080" that a user might reasonably expect to work.
                throw new ParseException("must start with a scheme, for example http://"
                        + segment);
            }
        }

        var host = "";
        if ((!scheme.isEmpty() || !rest.startsWith("///")) && rest.startsWith("//")) {
            var authority = rest.substring(2);
            var slash = authority.indexOf('/');
            if (slash >= 0) {
                authority = authority.substring(0, slash);
            }
            host = parseAuthority(authority);
        }

        return new Parsed(scheme, host);
    }

    private static String parseAuthority(String authority) throws ParseException {
        var at = authority.lastIndexOf('@');
        var host = parseHost(at < 0 ? authority : authority.substring(at + 1));
        if (at < 0) {
            return host;
        }

        var userinfo = authority.substring(0, at);
        if (!validUserinfo(userinfo)) {
            return failUserinfo();
        }
        // Go unescapes username and password separately, but either failing is the same rejection.
        var colon = userinfo.indexOf(':');
        if (colon < 0) {
            checkEscapes(userinfo);
        } else {
            checkEscapes(userinfo.substring(0, colon));
            checkEscapes(userinfo.substring(colon + 1));
        }
        return host;
    }

    private static String failUserinfo() throws ParseException {
        throw new ParseException("has invalid credentials before \"@\"");
    }

    private static String parseHost(String host) throws ParseException {
        if (host.startsWith("[")) {
            var close = host.lastIndexOf(']');
            if (close < 0) {
                throw new ParseException("is missing \"]\" in its IPv6 host");
            }
            requireOptionalPort(host.substring(close + 1));
        } else {
            var colon = host.lastIndexOf(':');
            if (colon >= 0) {
                requireOptionalPort(host.substring(colon));
            }
        }

        // unescape(host, encodeHost): rejects bad %-escapes and characters that are illegal in a
        // host, which is what turns "http://ho st:1" into an error rather than a lookup.
        for (var i = 0; i < host.length(); i++) {
            var c = host.charAt(i);
            if (c == '%') {
                if (i + 2 >= host.length() || !isHex(host.charAt(i + 1)) || !isHex(host.charAt(i + 2))) {
                    throw new ParseException("contains an invalid escape in its host");
                }
                i += 2;
                continue;
            }
            if (c < 0x80 && shouldEscapeInHost(c)) {
                throw new ParseException("contains an invalid character in its host: \"" + c + "\"");
            }
        }
        return host;
    }

    /**
     * Go's {@code validOptionalPort}: empty, or a colon followed only by digits. Note that it does
     * not range-check, so {@code :99999} parses; the dialer finds out later.
     */
    private static void requireOptionalPort(String colonPort) throws ParseException {
        if (colonPort.isEmpty()) {
            return;
        }
        if (colonPort.charAt(0) != ':') {
            throw new ParseException("has an invalid port \"" + colonPort + "\" after its host");
        }
        for (var i = 1; i < colonPort.length(); i++) {
            if (!isDigit(colonPort.charAt(i))) {
                throw new ParseException("has an invalid port \"" + colonPort + "\" after its host");
            }
        }
    }

    private static void checkEscapes(String value) throws ParseException {
        for (var i = 0; i < value.length(); i++) {
            if (value.charAt(i) != '%') {
                continue;
            }
            if (i + 2 >= value.length() || !isHex(value.charAt(i + 1)) || !isHex(value.charAt(i + 2))) {
                throw new ParseException("contains an invalid escape in its credentials");
            }
            i += 2;
        }
    }

    /** Go's {@code validUserinfo}: unreserved / sub-delims / ":" / "%". */
    private static boolean validUserinfo(String value) {
        for (var i = 0; i < value.length(); i++) {
            var c = value.charAt(i);
            if (isAlpha(c) || isDigit(c)) continue;
            switch (c) {
                case '-', '.', '_', ':', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '%', '@' -> {
                    continue;
                }
                default -> {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Go's {@code shouldEscape(c, encodeHost)} inverted: true means the byte may not appear
     * literally in a host.
     */
    private static boolean shouldEscapeInHost(char c) {
        if (isAlpha(c) || isDigit(c)) return false;
        return switch (c) {
            case '-', '_', '.', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=',
                 ':', '[', ']', '<', '>', '"' -> false;
            default -> true;
        };
    }

    private static boolean isAlpha(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isHex(char c) {
        return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /**
     * Golden vectors, generated from the vendored Go dialer. The Go half of this table lives in
     * {@code src-go/server/proxyurl_test.go}; the two must agree.
     * Run with: {@code java -ea -cp build/classes/java/main burp.control.ProxyUrl}
     */
    public static void main(String[] args) {
        String[][] golden = {
                {"http://127.0.0.1:8080", "ok"},
                {"https://proxy.example.com:443", "ok"},
                {"http://user:pass@proxy.example.com:3128", "ok"},
                {"socks5://127.0.0.1:1080", "ok"},
                {"socks5h://127.0.0.1:1080", "ok"},
                {"socks4://127.0.0.1:1080", "ok"},
                {"socks4a://127.0.0.1:1080", "ok"},
                {"http://proxy.example.com", "ok"},
                {"http://[::1]:8080", "ok"},
                {"HTTP://127.0.0.1:8080", "ok"},
                {"http://user:p%40ss@h:1", "ok"},
                {"http://127.0.0.1:8080/path", "ok"},
                {"http://127.0.0.1:8080?q=1", "ok"},
                // Go does not range-check the port, and an empty one is legal.
                {"http://127.0.0.1:99999", "ok"},
                {"http://h:", "ok"},
                {"http://user@h", "ok"},
                {"http://:pass@h", "ok"},
                {"ftp://127.0.0.1:21", "bad"},
                {"socks://127.0.0.1:1080", "bad"},
                {"127.0.0.1:8080", "bad"},
                {"proxy.example.com", "bad"},
                {"http://", "bad"},
                {"http:///path", "bad"},
                {"://127.0.0.1", "bad"},
                {"http://127.0.0.1:abc", "bad"},
                {"http://ho st:1", "bad"},
                {"ht tp://127.0.0.1", "bad"},
                {"http://%zz@h:1", "bad"},
                {"//127.0.0.1:8080", "bad"},
        };

        for (var row : golden) {
            var expected = row[1].equals("ok");
            var actual = isValid(row[0]);
            if (expected != actual) {
                throw new AssertionError("golden mismatch for \"" + row[0] + "\": expected "
                        + row[1] + ", got " + (actual ? "ok" : "bad: " + problem(row[0])));
            }
        }

        check(problem(null) == null, "null means direct/inherit");
        check(problem("") == null && problem("   ") == null, "empty means direct/inherit");
        check(problem("  http://127.0.0.1:8080  ") == null, "surrounding whitespace is trimmed");
        check(problem("http://" + "a".repeat(5000)) != null, "an absurd value is refused");

        // Every rejection has to say something a user can act on.
        for (var row : golden) {
            if (row[1].equals("bad")) {
                var why = problem(row[0]);
                check(why != null && !why.isBlank(), "\"" + row[0] + "\" has a reason");
            }
        }

        System.out.println("ProxyUrl self-check passed (" + golden.length + " golden vectors)");
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
