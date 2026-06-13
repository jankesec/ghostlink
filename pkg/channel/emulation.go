package channel

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"

	"github.com/byjanke/ghostlink/pkg/traffic"
)

func secureIntn(n int) int {
	var b [8]byte
	crand.Read(b[:])
	return int(binary.LittleEndian.Uint64(b[:]) % uint64(n))
}

// --- Realistic Domain Generation ---

var realisticPrefixes = []string{
	"api", "cdn", "static", "assets", "img", "data", "v1", "v2",
	"prod", "staging", "dev", "app", "m", "mobile", "ws", "stream",
	"analytics", "metrics", "logs", "events", "telemetry",
}

var realisticNames = []string{
	"firebase", "cloudfront", "akamai", "fastly", "cloudflare",
	"appengine", "lambda", "azureedge", "s3", "storage",
	"analytics-cdn", "metrics-api", "telemetry-gateway",
}

func GenerateRealisticDomain(baseDomain string) string {
	prefix := realisticPrefixes[secureIntn(len(realisticPrefixes))]
	name := realisticNames[secureIntn(len(realisticNames))]
	return prefix + "." + name + "." + baseDomain
}

// --- Stealth DNS Query Builder ---

func BuildStealthDNSQuery(data []byte, baseDomain string) []byte {
	encoded := base64.RawURLEncoding.EncodeToString(data)

	decoyLabels := []string{
		"a" + randomHex(3),
		"b" + randomHex(4),
		randomHex(5),
	}

	numDecoys := secureIntn(3)
	var parts []string
	parts = append(parts, encoded)

	remaining := 250 - len(encoded) - len(baseDomain)
	for i := 0; i < numDecoys && remaining > 100; i++ {
		decoy := decoyLabels[i]
		parts = append(parts, decoy)
		remaining -= len(decoy) + 1
	}

	prefix := realisticPrefixes[secureIntn(len(realisticPrefixes))]
	parts = append(parts, prefix)

	fqdn := strings.Join(parts, ".") + "." + baseDomain
	if len(fqdn) > 253 {
		fqdn = encoded + "." + baseDomain
	}

	var msg []byte
	msg = append(msg, byte(secureIntn(65536)>>8), byte(secureIntn(256)))
	msg = append(msg, 0x01, 0x00)
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	for _, label := range strings.Split(fqdn, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)

	queryTypes := []uint16{1, 16, 5, 28}
	qtype := queryTypes[secureIntn(len(queryTypes))]
	msg = append(msg, byte(qtype>>8), byte(qtype&0xFF))
	msg = append(msg, 0x00, 0x01)

	return msg
}

// --- CNAME Chaining ---

func BuildCNAMEChainQuery(data []byte, baseDomain string, hops int) []byte {
	if hops < 1 {
		hops = 2
	}
	if hops > 5 {
		hops = 5
	}

	encoded := base64.RawURLEncoding.EncodeToString(data)
	chunkSize := (len(encoded) + hops - 1) / hops

	var chainLabels []string
	for i := 0; i < hops; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		if start < len(encoded) {
			chainLabels = append(chainLabels, encoded[start:end])
		}
	}

	fqdn := chainLabels[0] + "." + baseDomain

	var msg []byte
	msg = append(msg, byte(secureIntn(65536)>>8), byte(secureIntn(256)))
	msg = append(msg, 0x01, 0x00)
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	for _, label := range strings.Split(fqdn, ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x05)
	msg = append(msg, 0x00, 0x01)

	return msg
}

// --- Stealth HTTP Request Builder ---

func BuildStealthHTTPRequest(data []byte, targetURL string) (method, path string, headers map[string]string, body []byte) {
	methods := []string{"GET", "POST", "HEAD"}
	method = methods[secureIntn(len(methods))]

	paths := []string{
		"/api/v2/analytics", "/api/v1/events", "/data/metrics",
		"/collect", "/telemetry", "/ping", "/health", "/status",
		"/v1/track", "/batch", "/beacon",
	}
	path = paths[secureIntn(len(paths))]

	encoded := base64.RawURLEncoding.EncodeToString(data)

	headers = map[string]string{
		"User-Agent":      traffic.CommonUserAgents[secureIntn(len(traffic.CommonUserAgents))],
		"Accept":          "application/json, text/plain, */*",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"Cache-Control":   "no-cache",
		"Connection":      "keep-alive",
		"Content-Type":    "application/json",
	}

	if method == "POST" {
		body = []byte(`{"session_id":"` + encoded + `","timestamp":` + time.Now().Format("20060102150405") + `}`)
	} else {
		if len(encoded) > 1 {
			mid := len(encoded) / 2
			headers["Cookie"] = "session=" + encoded[:mid] + "; track=" + encoded[mid:]
		}
	}

	return
}

// --- Dummy Traffic Generator ---

type DummyTraffic struct {
	stopCh   chan struct{}
	interval time.Duration
}

func NewDummyTraffic(interval time.Duration) *DummyTraffic {
	if interval == 0 {
		interval = 5 * time.Second
	}
	return &DummyTraffic{
		stopCh:   make(chan struct{}),
		interval: interval,
	}
}

func (d *DummyTraffic) StartDNS(ch Channel, domain string) {
	go func() {
		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				noise := randomNoise(16 + secureIntn(48))
				query := BuildStealthDNSQuery(noise, domain)
				_ = query
				ch.Send(noise)
			case <-d.stopCh:
				return
			}
		}
	}()
}

func (d *DummyTraffic) StartHTTP(ch Channel, targetURL string) {
	go func() {
		ticker := time.NewTicker(d.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				noise := randomNoise(32 + secureIntn(64))
				_, _, _, _ = BuildStealthHTTPRequest(noise, targetURL)
				ch.Send(noise)
			case <-d.stopCh:
				return
			}
		}
	}()
}

func (d *DummyTraffic) Stop() {
	close(d.stopCh)
}

func randomNoise(size int) []byte {
	data := make([]byte, size)
	crand.Read(data)
	return data
}

func randomHex(n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[secureIntn(len(hexChars))]
	}
	return string(b)
}
