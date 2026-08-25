package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	utls "github.com/bogdanfinn/utls"
)

// ConfigurationHeaderKey is the name of the header field that contains the RoundTripper configuration.
// Note that this key can only start with one capital letter and the rest in lowercase.
// Unfortunately, this seems to be a limitation of Burp's Extender API.
const ConfigurationHeaderKey = "Awesometlsconfig"

var (
	s *fhttp.Server

	// proxy and isProxyOn are read and written from request handlers, which fhttp runs
	// concurrently, so they need a lock. The intercept proxy is deliberately a single global:
	// starting and stopping it per request would rebind its port constantly and cut live
	// connections, which is why UseInterceptedFingerprint has to stay a global setting.
	proxyMu   sync.Mutex
	proxy     *interceptProxy
	isProxyOn bool
)

func init() {
	s = &fhttp.Server{}
}

func StartServer(addr string) error {
	if addr == "" {
		return fmt.Errorf("address must be provided")
	}

	s = &fhttp.Server{}

	ca, private, err := NewCertificateAuthority()
	if err != nil {
		return fmt.Errorf("NewCertificateAuthority, err: %w", err)
	}

	m := fhttp.NewServeMux()
	m.HandleFunc("/", func(w fhttp.ResponseWriter, req *fhttp.Request) {
		configHeader := req.Header.Get(ConfigurationHeaderKey)
		req.Header.Del(ConfigurationHeaderKey)

		config, err := ParseTransportConfig(configHeader)
		if err != nil {
			writeError(w, err)
			return
		}

		if err = syncProxyState(config.UseInterceptedFingerprint, config.InterceptProxyAddr, config.BurpAddr); err != nil {
			writeError(w, err)
			return
		}

		if config.UseInterceptedFingerprint {
			if interceptedFingerprint := interceptedClientHello(); interceptedFingerprint != "" {
				config.HexClientHello = HexClientHello(interceptedFingerprint)
			}
		}

		client, err := NewClient(config)
		if err != nil {
			writeError(w, err)
			return
		}

		req.URL.Host = config.Host
		req.URL.Scheme = config.Scheme
		req.RequestURI = ""
		req.Header[fhttp.HeaderOrderKey] = config.HeaderOrder
		// The content-length header is already set by the client (internally).
		// Leaving it here causes strange '400 bad request' errors from the destination, so we remove it.
		req.Header.Del("Content-Length")

		res, err := client.Do(req)
		if err != nil {
			writeError(w, err)
			return
		}

		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			writeError(w, err)
			return
		}

		// Write the response (back to burp).
		for k := range res.Header {
			vv := res.Header.Values(k)
			for _, v := range vv {
				// The response body is already automatically decompressed, so we need to update the Content-Length header accordingly.
				// Not doing so will cause the response writer to return an error.
				if k == "Content-Length" {
					w.Header().Add(k, fmt.Sprintf("%d", len(body)))
				} else {
					w.Header().Add(k, v)
				}
			}
		}
		w.WriteHeader(res.StatusCode)
		w.Write(body)
	})

	s.Addr = addr
	s.Handler = m
	s.TLSConfig = &utls.Config{
		Certificates: []utls.Certificate{
			{
				Certificate: [][]byte{ca.Raw},
				PrivateKey:  private,
				Leaf:        ca,
			},
		},
		NextProtos: []string{"http/1.1"},
	}

	generation := beginSpoof()

	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		wrapped := fmt.Errorf("listen, err: %w", err)
		setSpoofStatus(generation, StateFailed, "", wrapped.Error())
		return wrapped
	}

	// The address the socket is actually bound to, which is what Java must be told. The requested
	// address is not the same thing once a port of 0 or a changed setting is involved.
	setSpoofStatus(generation, StateRunning, listener.Addr().String(), "")

	tlsListener := utls.NewListener(listener, s.TLSConfig)

	if err := s.Serve(tlsListener); err != nil {
		// Shutdown makes Serve return ErrServerClosed. That is the normal way this function ends,
		// not a failure, and reporting it as FAILED would leave the UI claiming the server crashed
		// every time the extension is unloaded.
		if errors.Is(err, fhttp.ErrServerClosed) {
			setSpoofStatus(generation, StateStopped, "", "")
			return fmt.Errorf("Server stopped")
		}
		wrapped := fmt.Errorf("serve, err: %w", err)
		setSpoofStatus(generation, StateFailed, "", wrapped.Error())
		return wrapped
	}

	setSpoofStatus(generation, StateStopped, "", "")
	return nil
}

// syncProxyState starts or stops the shared intercept proxy to match the request's global flag.
func syncProxyState(wanted bool, interceptAddr, burpAddr string) error {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	if wanted == isProxyOn {
		return nil
	}

	if wanted {
		if err := startProxyLocked(interceptAddr, burpAddr); err != nil {
			return err
		}
		isProxyOn = true
		return nil
	}

	if err := stopProxyLocked(); err != nil {
		return err
	}
	isProxyOn = false
	return nil
}

// interceptedClientHello returns the most recently captured ClientHello, or "" if there is none.
func interceptedClientHello() string {
	proxyMu.Lock()
	p := proxy
	proxyMu.Unlock()

	if p == nil {
		return ""
	}
	return p.getTLSFingerprint()
}

func StartProxy(interceptAddr, burpAddr string) error {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	if err := startProxyLocked(interceptAddr, burpAddr); err != nil {
		return err
	}
	isProxyOn = true
	return nil
}

func startProxyLocked(interceptAddr, burpAddr string) error {
	setInterceptStatus(StateStarting, "", "")
	setBurpUpstream(burpAddr, "")

	p, err := newInterceptProxy(interceptAddr, burpAddr)
	if err != nil {
		setInterceptStatus(StateFailed, "", err.Error())
		setBurpUpstream(burpAddr, err.Error())
		return err
	}

	proxy = p
	setInterceptStatus(StateRunning, p.listener.Addr().String(), "")

	go p.Start()

	return nil
}

func StopProxy() error {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	if err := stopProxyLocked(); err != nil {
		return err
	}
	isProxyOn = false
	return nil
}

func stopProxyLocked() error {
	if proxy == nil {
		return nil
	}
	err := proxy.Stop()
	proxy = nil
	if err != nil {
		setInterceptStatus(StateFailed, "", err.Error())
		return err
	}
	setInterceptStatus(StateStopped, "", "")
	setBurpUpstream("", "")
	return nil
}

func StopServer() error {
	err := s.Shutdown(context.Background())
	setSpoofStatus(currentSpoofGeneration(), StateStopped, "", "")
	return err
}

func writeError(w fhttp.ResponseWriter, err error) {
	w.WriteHeader(500)
	fmt.Fprint(w, fmt.Errorf("Awesome TLS error: %s", err))
	fmt.Println(err)
}
