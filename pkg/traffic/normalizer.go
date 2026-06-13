package traffic

import (
	crand "crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

type TrafficProfile string

const (
	DNSTraffic  TrafficProfile = "dns"
	HTTPTraffic TrafficProfile = "http"
	ICMPTraffic TrafficProfile = "icmp"
	TCPTraffic  TrafficProfile = "tcp"
	IdleTraffic TrafficProfile = "idle"
)

type Normalizer struct {
	profile      TrafficProfile
	minInterval  time.Duration
	maxInterval  time.Duration
	lastSend     time.Time
	burstCount   int
	maxBurst     int
	jitterFactor float64
	mu           sync.Mutex
}

func NewNormalizer(profile TrafficProfile) *Normalizer {
	n := &Normalizer{profile: profile}
	switch profile {
	case DNSTraffic:
		n.minInterval = 500 * time.Millisecond
		n.maxInterval = 5 * time.Second
		n.maxBurst = 3
		n.jitterFactor = 0.3
	case HTTPTraffic:
		n.minInterval = 100 * time.Millisecond
		n.maxInterval = 2 * time.Second
		n.maxBurst = 10
		n.jitterFactor = 0.2
	case ICMPTraffic:
		n.minInterval = 800 * time.Millisecond
		n.maxInterval = 3 * time.Second
		n.maxBurst = 2
		n.jitterFactor = 0.25
	case TCPTraffic:
		n.minInterval = 50 * time.Millisecond
		n.maxInterval = 1 * time.Second
		n.maxBurst = 15
		n.jitterFactor = 0.15
	default:
		n.minInterval = 500 * time.Millisecond
		n.maxInterval = 3 * time.Second
		n.maxBurst = 5
		n.jitterFactor = 0.3
	}
	return n
}

func (n *Normalizer) WaitForSlot() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.burstCount >= n.maxBurst {
		delay := n.randomInterval()
		n.mu.Unlock()
		time.Sleep(delay)
		n.mu.Lock()
		n.burstCount = 0
	}
}

func (n *Normalizer) RecordSend() {
	n.burstCount++
	n.lastSend = time.Now()
}

func (n *Normalizer) randomInterval() time.Duration {
	base := n.minInterval
	if n.maxInterval > n.minInterval {
		base += time.Duration(secureInt63n(int64(n.maxInterval - n.minInterval)))
	}
	jitter := time.Duration(float64(base) * n.jitterFactor * (secureFloat64()*2 - 1))
	d := base + jitter
	if d < n.minInterval {
		d = n.minInterval
	}
	return d
}

func secureInt63n(n int64) int64 {
	var b [8]byte
	crand.Read(b[:])
	v := int64(binary.LittleEndian.Uint64(b[:]) >> 1)
	return v % n
}

func secureFloat64() float64 {
	var b [8]byte
	crand.Read(b[:])
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / (1 << 53)
}

func (n *Normalizer) ShouldPad() bool {
	return time.Since(n.lastSend) > n.minInterval*3
}

var CommonUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
}
