package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubProvider struct {
	killed bool
}

func (stubProvider) ListSessions() []SessionInfo                       { return []SessionInfo{{ID: 7, Active: true}} }
func (stubProvider) GetActiveID() uint32                               { return 7 }
func (stubProvider) SetActive(uint32) bool                             { return true }
func (s *stubProvider) KillSession(uint32)                             { s.killed = true }
func (stubProvider) ExecOnSession(uint32, string) error                { return nil }
func (stubProvider) RunModuleOnSession(uint32, string, []string) error { return nil }
func (stubProvider) ListModules() []map[string]string                  { return nil }

func TestLoopbackAddressPolicy(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		if err := validateLoopbackAddress(addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8888", "192.0.2.1:8888", "bad"} {
		if err := validateLoopbackAddress(addr); err == nil {
			t.Errorf("%s unexpectedly accepted", addr)
		}
	}
}

func TestHealthAndInfoHandlers(t *testing.T) {
	provider := &stubProvider{}
	server := NewServer("127.0.0.1:0", provider)

	health := httptest.NewRecorder()
	server.handleHealth(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}

	info := httptest.NewRecorder()
	server.handleInfo(info, httptest.NewRequest(http.MethodGet, "/api/info", nil))
	var payload map[string]interface{}
	if err := json.NewDecoder(info.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["api_scope"] != "loopback-only" || payload["sessions"] != float64(1) {
		t.Fatalf("unexpected info payload: %#v", payload)
	}

	wrongMethod := httptest.NewRecorder()
	server.handleHealth(wrongMethod, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("method policy not enforced: %d %#v", wrongMethod.Code, wrongMethod.Header())
	}
}

func TestSessionKillRequiresAnExplicitMutatingMethod(t *testing.T) {
	provider := &stubProvider{}
	server := NewServer("127.0.0.1:0", provider)

	get := httptest.NewRecorder()
	server.handleSession(get, httptest.NewRequest(http.MethodGet, "/api/sessions/7/kill", nil))
	if provider.killed || get.Code != http.StatusNotFound {
		t.Fatalf("GET kill mutated state: killed=%v status=%d", provider.killed, get.Code)
	}

	post := httptest.NewRecorder()
	server.handleSession(post, httptest.NewRequest(http.MethodPost, "/api/sessions/7/kill", nil))
	if !provider.killed || post.Code != http.StatusOK {
		t.Fatalf("POST kill failed: killed=%v status=%d", provider.killed, post.Code)
	}
}
