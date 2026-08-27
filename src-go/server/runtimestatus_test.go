package server

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestRuntimeStatusDefaultsToStopped(t *testing.T) {
	setSpoofStatus(beginSpoof(), StateStopped, "", "")
	setInterceptStatus(StateStopped, "", "")
	setBurpUpstream("", "")

	s := RuntimeStatus()
	if s.Spoof.State != StateStopped || s.Spoof.ActualAddress != "" {
		t.Fatalf("expected a stopped spoof listener with no address, got %+v", s.Spoof)
	}
	if s.BurpUpstreamEndpoint != "" {
		t.Fatalf("expected the Burp upstream to be unknown, got %q", s.BurpUpstreamEndpoint)
	}
}

func TestRuntimeStatusReportsRealAddresses(t *testing.T) {
	setSpoofStatus(beginSpoof(), StateRunning, "127.0.0.1:8887", "")
	setInterceptStatus(StateFailed, "", "bind: address already in use")
	setBurpUpstream("127.0.0.1:8080", "")

	var decoded RuntimeStatusSnapshot
	if err := json.Unmarshal([]byte(RuntimeStatusJSON()), &decoded); err != nil {
		t.Fatalf("status JSON does not round trip: %v", err)
	}
	if decoded.Spoof.ActualAddress != "127.0.0.1:8887" {
		t.Fatalf("spoof address lost in transit: %+v", decoded.Spoof)
	}
	if decoded.Intercept.State != StateFailed || decoded.Intercept.LastError == "" {
		t.Fatalf("a failed listener must carry its error: %+v", decoded.Intercept)
	}
	// A failed listener must not report an address; Java uses this to decide whether the
	// configured value is live.
	if decoded.Intercept.ActualAddress != "" {
		t.Fatalf("a failed listener must have no address, got %q", decoded.Intercept.ActualAddress)
	}
}

// The status is written by the goroutine that owns a listener and read from the request handler,
// so it has to be safe under -race.
func TestRuntimeStatusIsRaceFree(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				setSpoofStatus(beginSpoof(), StateRunning, "127.0.0.1:8887", "")
				setInterceptStatus(StateStarting, "", "")
				setBurpUpstream("127.0.0.1:8080", "")
			}
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = RuntimeStatusJSON()
			}
		}()
	}
	wg.Wait()
}

// The intercept proxy's on/off state is flipped from request handlers, which run concurrently.
func TestProxyStateIsRaceFree(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = interceptedClientHello()
			}
		}()
	}
	wg.Wait()
}

// Reloading the extension overlaps a server that is shutting down with one that is starting. The
// goroutine unwinding from the old Serve must not be able to report STOPPED over the new server's
// RUNNING, or Java is told there is no listener while a socket is bound.
func TestStoppingServerCannotClobberANewerOne(t *testing.T) {
	old := beginSpoof()
	setSpoofStatus(old, StateRunning, "127.0.0.1:8887", "")

	// A reload: the new StartServer claims the slot and binds.
	fresh := beginSpoof()
	setSpoofStatus(fresh, StateRunning, "127.0.0.1:8887", "")

	// Only now does the previous Serve call unwind and try to report that it stopped.
	setSpoofStatus(old, StateStopped, "", "")

	if got := RuntimeStatus().Spoof; got.State != StateRunning || got.ActualAddress != "127.0.0.1:8887" {
		t.Fatalf("a stopping server overwrote the current one: %+v", got)
	}

	// The current one may still report its own stop.
	setSpoofStatus(fresh, StateStopped, "", "")
	if got := RuntimeStatus().Spoof; got.State != StateStopped {
		t.Fatalf("the current server could not report its own stop: %+v", got)
	}
}
