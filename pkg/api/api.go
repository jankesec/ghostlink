package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
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
	mux := http.NewServeMux()

	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/sessions/", s.handleSession)
	mux.HandleFunc("/api/modules", s.handleModules)

	s.server = &http.Server{Addr: s.addr, Handler: mux}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api listen: %w", err)
	}

	go s.server.Serve(ln)
	return nil
}

func (s *Server) Close() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		sessions := s.provider.ListSessions()
		writeJSON(w, map[string]interface{}{
			"sessions": sessions,
			"active":   s.provider.GetActiveID(),
		})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing session id", 400)
		return
	}

	var id uint32
	fmt.Sscanf(parts[0], "%d", &id)
	if id == 0 {
		http.Error(w, "invalid session id", 400)
		return
	}

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case r.Method == "DELETE" || action == "kill":
		s.provider.KillSession(id)
		writeJSON(w, map[string]string{"status": "killed"})

	case action == "use" && r.Method == "POST":
		if s.provider.SetActive(id) {
			writeJSON(w, map[string]string{"status": "active"})
		} else {
			http.Error(w, "session not found", 404)
		}

	case action == "exec" && r.Method == "POST":
		var req ExecRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if err := s.provider.ExecOnSession(id, req.Command); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]string{"status": "sent"})

	case action == "module" && r.Method == "POST":
		var req ModuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if err := s.provider.RunModuleOnSession(id, req.Module, req.Args); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]string{"status": "sent"})

	default:
		http.Error(w, "not found", 404)
	}
}

func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	writeJSON(w, map[string]interface{}{
		"modules": s.provider.ListModules(),
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
