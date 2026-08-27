package server

import (
	"encoding/json"
	"sync"
)

// Listener states, mirrored by burp.control.RuntimeStatus.State on the Java side.
const (
	StateStarting = "STARTING"
	StateRunning  = "RUNNING"
	StateStopped  = "STOPPED"
	StateFailed   = "FAILED"
)

// ListenerStatus is what one listener is actually doing.
//
// ActualAddress is the address the socket is really bound to, taken from the listener after the
// bind succeeded, not the address that was requested. They differ whenever a port of 0 is used, and
// more importantly the requested address is meaningless while the state is FAILED or STOPPED.
type ListenerStatus struct {
	State         string `json:"state"`
	ActualAddress string `json:"actualAddress"`
	LastError     string `json:"lastError"`
}

// RuntimeStatusSnapshot is an immutable view of everything Go owns that Java would otherwise have
// to guess at.
//
// Java must not infer any of this from the configured settings or from whether a thread is alive.
// The case that matters is the spoof listener: after its address is changed in the settings, the
// running server keeps serving on the old one, and treating the new value as live would point every
// request at a port nothing is bound to. See ADR-0001 section 3.
type RuntimeStatusSnapshot struct {
	Spoof     ListenerStatus `json:"spoof"`
	Intercept ListenerStatus `json:"intercept"`

	// BurpUpstreamEndpoint is the Burp proxy address the intercept proxy is dialling. It is
	// deliberately NOT the interface Burp's own proxy listener is bound to, which the Montoya API
	// does not expose; empty means unknown, and Java reports it as unavailable rather than
	// assuming 127.0.0.1.
	BurpUpstreamEndpoint string `json:"burpUpstreamEndpoint"`
	BurpUpstreamError    string `json:"burpUpstreamError"`
}

var (
	statusMu sync.RWMutex
	status   = RuntimeStatusSnapshot{
		Spoof:     ListenerStatus{State: StateStopped},
		Intercept: ListenerStatus{State: StateStopped},
	}

	// spoofGeneration identifies the current StartServer call. Reloading the extension overlaps a
	// server that is shutting down with one that is starting, and without this the goroutine
	// unwinding from the old Serve writes STOPPED after the new one has already written RUNNING —
	// leaving Java told there is no listener while a socket is very much bound.
	spoofGeneration int
)

// beginSpoof claims the status slot for a new StartServer call.
func beginSpoof() int {
	statusMu.Lock()
	defer statusMu.Unlock()
	spoofGeneration++
	status.Spoof = ListenerStatus{State: StateStarting}
	return spoofGeneration
}

// currentSpoofGeneration is what StopServer reports against, so a stop can only ever describe the
// server that is actually current.
func currentSpoofGeneration() int {
	statusMu.RLock()
	defer statusMu.RUnlock()
	return spoofGeneration
}

// RuntimeStatus returns a copy, so a caller can never observe a half-updated snapshot.
func RuntimeStatus() RuntimeStatusSnapshot {
	statusMu.RLock()
	defer statusMu.RUnlock()
	return status
}

// RuntimeStatusJSON is what crosses the cgo boundary.
func RuntimeStatusJSON() string {
	encoded, err := json.Marshal(RuntimeStatus())
	if err != nil {
		// Marshalling a struct of strings cannot fail, but returning an empty object keeps the
		// Java side parsing rather than treating a marshalling bug as "no listeners".
		return "{}"
	}
	return string(encoded)
}

// setSpoofStatus records the state of one particular StartServer call, and does nothing if that
// call is no longer the current one.
func setSpoofStatus(generation int, state, actualAddress, lastError string) {
	statusMu.Lock()
	defer statusMu.Unlock()
	if generation != spoofGeneration {
		return
	}
	status.Spoof = ListenerStatus{State: state, ActualAddress: actualAddress, LastError: lastError}
}

func setInterceptStatus(state, actualAddress, lastError string) {
	statusMu.Lock()
	defer statusMu.Unlock()
	status.Intercept = ListenerStatus{State: state, ActualAddress: actualAddress, LastError: lastError}
}

func setBurpUpstream(endpoint, lastError string) {
	statusMu.Lock()
	defer statusMu.Unlock()
	status.BurpUpstreamEndpoint = endpoint
	status.BurpUpstreamError = lastError
}
