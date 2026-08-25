package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.Gson;

import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class Extension implements BurpExtension {
    private MontoyaApi api;
    private Gson gson;
    private Settings settings;
    private SettingsTab settingsTab;

    private static final String HEADER_KEY = "Awesometlsconfig";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.gson = new Gson();
        this.settings = new Settings(api);
        this.settingsTab = new SettingsTab(settings);

        api.extension().setName("Awesome TLS");
        api.extension().registerUnloadingHandler(this::unload);
        var ui = settingsTab.getUI();
        // Burp's own styling pass: font size, colors and table line spacing, matched to the
        // active theme. Cheaper and more correct than deriving all of that from UIManager.
        api.userInterface().applyThemeToComponent(ui);
        api.userInterface().registerSuiteTab("Awesome TLS", ui);
        // An HTTP handler sees traffic from every tool, so Repeater, Intruder and Scanner get the
        // spoofed fingerprint too. A Proxy handler would only cover browser traffic.
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                return RequestToBeSentAction.continueWith(processHttpRequest(requestToBeSent));
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        var listenAddress = settings.getSpoofProxyAddress();
        new Thread(() -> {
            // StartServer blocks for the lifetime of the server. A failure to bind returns within
            // milliseconds, so this optimistic status is corrected below before anyone can read it.
            settingsTab.setServerStatus("Running — listening on " + listenAddress, false);

            var err = ServerLibrary.INSTANCE.StartServer(listenAddress);

            // Reaching here means the server stopped, or never managed to start.
            if (!err.isEmpty()) {
                api.logging().logToError(err);

                if (err.contains("address already in use")) {
                    // Almost always a previous load of this extension. A native library cannot be
                    // unloaded, so reloading leaves the old Go runtime running; if it still holds
                    // the port, this instance never binds and traffic keeps working — served by the
                    // previous build. Saying only "address already in use" leaves the user to
                    // conclude their change took effect when it did not.
                    var message = "Not serving — " + listenAddress + " is already in use, most "
                            + "likely by a previous load of this extension. Traffic is still being "
                            + "handled by that older instance, so changes to the native library "
                            + "have NOT taken effect. Restart Burp to clear it.";
                    api.logging().logToError("Awesome TLS: " + message);
                    settingsTab.setServerStatus(message, true);
                } else {
                    settingsTab.setServerStatus("Stopped — " + err, true);

                    if (!err.contains("Server stopped")) {
                        api.extension().unload(); // fatal error; disable the extension
                    }
                }
            } else {
                settingsTab.setServerStatus("Stopped", true);
            }
        }).start();
    }

    /**
     * Releases everything this extension holds, within a bounded time.
     * <p>
     * The MCP listener goes first and unconditionally: it is the only thing here that is reachable
     * from outside this process, and ADR-0001 section 14.2 puts closing it ahead of being able to
     * record that it closed.
     */
    private void unload() {
        try {
            settings.mcpServer().stop();
        } catch (RuntimeException e) {
            api.logging().logToError("Awesome TLS: could not stop the AI Control listener: " + e);
        }

        try {
            var err = ServerLibrary.INSTANCE.StopServer();
            if (!err.isEmpty()) {
                api.logging().logToError(err);
            }
        } catch (Throwable e) {
            api.logging().logToError("Awesome TLS: could not stop the local server: " + e);
        }
    }

    private HttpRequest processHttpRequest(HttpRequestToBeSent request) {
        try {
            // The rewritten request below is itself sent by Burp, so it comes back through this
            // handler. Without this guard it would be rewritten again, endlessly.
            if (request.hasHeader(HEADER_KEY)) {
                return request;
            }

            // Burp's own traffic (update checks, Collaborator polling, the BApp store) must reach
            // its real destination; redirecting it through the spoof server would break it.
            if (request.toolSource().isFromTool(ToolType.SUITE)) {
                return request;
            }

            var requestURL = new URI(request.url()).toURL();

            if (requestURL.getHost().equals("awesome-tls-error")) {
                throw new Error(new String(request.body().getBytes(), StandardCharsets.UTF_8));
            }

            var headerOrder = new String[request.headers().size()];
            for (var i = 0; i < request.headers().size(); i++) {
                headerOrder[i] = request.headers().get(i).name();
            }

            var transportConfig = settings.toTransportConfig(requestURL.getHost());
            transportConfig.Host = requestURL.getHost();
            transportConfig.Scheme = requestURL.getProtocol();
            transportConfig.HeaderOrder = headerOrder;

            var goConfigJSON = gson.toJson(transportConfig);
            // The address the Go server is really listening on, not the configured one. Changing
            // the listen address does not move a running server, so using the configured value here
            // would send every request to a port nothing is bound to until the extension is
            // reloaded. See ADR-0001 section 12.
            var url = new URI("https://" + settings.activeSpoofProxyAddress()).toURL();
            var httpService = HttpService.httpService(url.getHost(), url.getPort(), Objects.equals(url.getProtocol(), "https"));

            return request.withService(httpService).withAddedHeader(HEADER_KEY, goConfigJSON);
        } catch (Exception e) {
            // Send the request unmodified rather than dropping it: losing traffic outright is a
            // worse failure than losing the spoofed fingerprint for one request.
            api.logging().logToError("Http request error: " + e);
            return request;
        }
    }
}
