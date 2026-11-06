package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/byjanke/ghostlink/internal/buildinfo"
	"github.com/byjanke/ghostlink/pkg/protocol"
)

type SessionInfo struct {
	ID     uint32 `json:"id"`
	Remote string `json:"remote"`
	Active bool   `json:"active"`
}

type ExecRequest struct {
	Command string `json:"command"`
}

type ModuleRequest struct {
	Module string   `json:"module"`
	Args   []string `json:"args"`
}

type SessionProvider interface {
	ListSessions() []SessionInfo
	GetActiveID() uint32
	SetActive(id uint32) bool
	KillSession(id uint32)
	ExecOnSession(id uint32, cmd string) error
	RunModuleOnSession(id uint32, module string, args []string) error
	ListModules() []map[string]string
}

type Server struct {
	addr     string
	provider SessionProvider
	server   *http.Server
	mu       sync.Mutex
}

func NewServer(addr string, provider SessionProvider) *Server {
	return &Server{
		addr:     addr,
		provider: provider,
	}
}

func (s *Server) Start() error {
	if err := validateLoopbackAddress(s.addr); err != nil {
		return err
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/sessions/", s.handleSession)
	mux.HandleFunc("/api/modules", s.handleModules)

	httpServer := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api listen: %w", err)
	}

	s.mu.Lock()
	s.server = httpServer
	s.mu.Unlock()
	go func() {
		_ = httpServer.Serve(ln)
	}()
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	server := s.server
	s.mu.Unlock()
	if server != nil {
		return server.Close()
	}
	return nil
}

func validateLoopbackAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("api address: %w", err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("api address must be loopback; got %q", host)
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"build":     buildinfo.String(),
		"protocol":  protocol.ProtocolVersion,
		"sessions":  len(s.provider.ListSessions()),
		"api_scope": "loopback-only",
	})
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		sessions := s.provider.ListSessions()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"sessions": sessions,
			"active":   s.provider.GetActiveID(),
		})
	default:
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing session id", 400)
		return
	}

	parsedID, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || parsedID == 0 {
		http.Error(w, "invalid session id", 400)
		return
	}
	id := uint32(parsedID)

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case (r.Method == http.MethodDelete && action == "") || (action == "kill" && r.Method == http.MethodPost):
		s.provider.KillSession(id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "killed"})

	case action == "use" && r.Method == "POST":
		if s.provider.SetActive(id) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
		} else {
			http.Error(w, "session not found", 404)
		}

	case action == "exec" && r.Method == "POST":
		var req ExecRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if err := s.provider.ExecOnSession(id, req.Command); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})

	case action == "module" && r.Method == "POST":
		var req ModuleRequest
		if err := decodeJSON(w, r, &req); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if err := s.provider.RunModuleOnSession(id, req.Module, req.Args); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})

	default:
		http.Error(w, "not found", 404)
	}
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", 405)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"modules": s.provider.ListModules(),
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
