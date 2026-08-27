package burp;


/**
 * Represents the configuration for transport.
 */
public class TransportConfig {
    /*
     * Destination as Go's url.URL.Host means it: "host:port", or a bare host when the request URL
     * carried no explicit port. Not just the hostname — the Go side assigns this to req.URL.Host,
     * where a bare host resolves to the scheme's default port.
     */
    public String Host;

    /**
     * Protocol scheme (HTTP or HTTPS).
     */
    public String Scheme;

    /**
     * Intercept ClientHello Proxy Address.
     */
    public String InterceptProxyAddr;

    /**
     * Burp Proxy Address.
     */
    public String BurpAddr;

    /**
     * The TLS fingerprint to use.
     */
    public String Fingerprint;

    /*
     * Hexadecimal Client Hello
     */
    public String HexClientHello;

    /*
     * Use intercepted fingerprint from request;
     */
    public Boolean UseInterceptedFingerprint;

    /**
     * The maximum amount of time to wait for an HTTP response.
     */
    public int HttpTimeout;

    /**
     * the order of headers to be sent in the request.
     */
    public String[] HeaderOrder;

    /**
     * External proxy URL (format: `http://user:pass@host:port`).
     */
    public String ExternalProxyUrl;
}
