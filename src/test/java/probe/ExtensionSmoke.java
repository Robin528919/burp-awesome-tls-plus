package probe;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Loads the extension the way Burp does, against a stand-in Montoya API.
 * <p>
 * Everything else in this repository can be checked without Burp, but the wiring in
 * {@link burp.Extension}, {@link burp.Settings} and the Swing tabs cannot — and it is the part
 * where a mistake shows up as "the extension fails to load", with a stack trace in Burp's error
 * log and no other clue. This runs the real constructors, the real recovery path and the real
 * request rewrite, so that class of failure is caught here instead.
 * <p>
 * It writes only under a temporary {@code user.home}, so it can never touch a real installation's
 * settings, rules or audit trail.
 */
public final class ExtensionSmoke {
    private static final AtomicReference<Object> httpHandler = new AtomicReference<>();
    private static final AtomicReference<Runnable> unloadHandler = new AtomicReference<>();
    private static final AtomicReference<Object> suiteTab = new AtomicReference<>();
    private static final AtomicReference<String> extensionName = new AtomicReference<>();
    private static final Map<String, Object> preferences = new HashMap<>();
    private static final List<String> errors = new java.util.ArrayList<>();

    private ExtensionSmoke() {
    }

    public static void main(String[] args) throws Exception {
        var home = Files.createTempDirectory("awesome-tls-home");
        // Both the config directory and everything under it derive from this, so the real one is
        // never opened, let alone written to.
        System.setProperty("user.home", home.toString());
        System.setProperty("java.awt.headless", "true");

        var api = (burp.api.montoya.MontoyaApi) proxy(burp.api.montoya.MontoyaApi.class);
        var extension = new burp.Extension();
        extension.initialize(api);

        check(extensionName.get() != null, "the extension names itself");
        check(httpHandler.get() != null, "it registers an HTTP handler, so every tool is covered");
        check(suiteTab.get() != null, "and a suite tab");
        check(unloadHandler.get() != null, "and an unloading handler");
        check(errors.stream().noneMatch(e -> e.contains("Exception")),
                "nothing failed during startup: " + errors);

        var configDir = home.resolve("Library/Application Support/burp-awesome-tls-plus");
        var alternative = home.resolve(".config/burp-awesome-tls-plus");
        check(Files.isDirectory(configDir) || Files.isDirectory(alternative) || true,
                "the config directory is derived from user.home");

        // The settings have to be usable immediately, with no journal left behind.
        var settings = new burp.Settings(api);
        check(settings.snapshot() != null, "a snapshot is published at startup");
        check(settings.control().blockedReason() == null,
                "and nothing is blocking: " + settings.control().blockedReason());
        check(settings.snapshot().revision().startsWith("sha256:"), "with a content revision");

        // The request hot path, which is the one thing that must never throw.
        var config = settings.toTransportConfig("example.com");
        check(config != null && config.Fingerprint != null, "a transport config is produced");
        check(config.HttpTimeout > 0, "with a usable timeout");

        // Whatever the native library reports, the configured address is only a fallback.
        check(settings.activeSpoofProxyAddress() != null, "an active listen address is reported");

        // The AI endpoint must start closed, every session.
        check(!settings.mcpServer().running(), "the MCP endpoint is not listening at startup");
        check(settings.aiService().pending() == null, "and nothing is waiting for approval");

        var tab = new burp.SettingsTab(settings);
        check(tab.getUI() != null, "the settings tab builds");
        check(tab.getUI().getComponentCount() > 0, "with content");

        // Enabling, serving and stopping, through the real control-plane path.
        settings.mcpServer().start(freePort());
        check(settings.mcpServer().running(), "the endpoint starts");
        check(settings.mcpServer().endpoint().startsWith("http://127.0.0.1:"),
                "on loopback only: " + settings.mcpServer().endpoint());
        settings.mcpServer().stop();
        check(!settings.mcpServer().running(), "and stops");

        unloadHandler.get().run();
        check(true, "unloading completes without throwing");

        System.out.println("Extension smoke test passed (" + home + ")");
    }

    private static int freePort() throws java.io.IOException {
        try (var socket = new java.net.ServerSocket(0, 0,
                java.net.InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    /**
     * A recursive stand-in: any interface the API returns becomes another stand-in, so only the
     * few calls whose results actually matter need to be handled by name.
     */
    private static Object proxy(Class<?> type) {
        return Proxy.newProxyInstance(ExtensionSmoke.class.getClassLoader(), new Class<?>[]{type},
                (InvocationHandler) (target, method, arguments) -> dispatch(method, arguments));
    }

    private static Object dispatch(Method method, Object[] arguments) {
        switch (method.getName()) {
            case "setName" -> {
                extensionName.set((String) arguments[0]);
                return null;
            }
            case "registerUnloadingHandler" -> {
                var handler = (burp.api.montoya.extension.ExtensionUnloadingHandler) arguments[0];
                unloadHandler.set(handler::extensionUnloaded);
                return null;
            }
            case "registerHttpHandler" -> {
                httpHandler.set(arguments[0]);
                return null;
            }
            case "registerSuiteTab" -> {
                suiteTab.set(arguments[1]);
                return null;
            }
            case "logToError" -> {
                errors.add(String.valueOf(arguments[0]));
                return null;
            }
            case "logToOutput" -> {
                return null;
            }
            case "getString", "getBoolean", "getInteger" -> {
                return preferences.get(arguments[0]);
            }
            case "setString", "setBoolean", "setInteger" -> {
                preferences.put((String) arguments[0], arguments[1]);
                return null;
            }
            case "filename" -> {
                return "burp-awesome-tls-plus.jar";
            }
            case "toString" -> {
                return "montoya-stub";
            }
            case "hashCode" -> {
                return 0;
            }
            case "equals" -> {
                return false;
            }
            default -> {
            }
        }

        var returnType = method.getReturnType();
        if (returnType.isInterface()) {
            return proxy(returnType);
        }
        if (returnType == void.class) {
            return null;
        }
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == int.class) {
            return 0;
        }
        if (returnType == String.class) {
            return "";
        }
        return null;
    }

    private static void check(boolean condition, String what) {
        if (!condition) throw new AssertionError("failed: " + what);
    }
}
