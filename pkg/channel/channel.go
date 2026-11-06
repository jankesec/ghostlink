package channel

import (
	"net"
	"sort"
	"sync"
)

type ChannelType string

const (
	DNSChannel        ChannelType = "dns"
	ICMPChannel       ChannelType = "icmp"
	HTTPChannel       ChannelType = "http"
	TCPISNChannel     ChannelType = "tcp_isn"
	IPIDChannel       ChannelType = "ip_id"
	TimingChannel     ChannelType = "timing"
	PacketSizeChannel ChannelType = "packet_size"
	WebSocketChannel  ChannelType = "websocket"
	DoHChannel        ChannelType = "doh"
)

type ChannelInfo struct {
	Type        ChannelType `json:"type"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Capability  float64     `json:"capability"`
}

type Channel interface {
	Info() ChannelInfo

	Connect(addr string) error

	Send(data []byte) error

	Recv() ([]byte, error)

	Close() error
}

type Listener interface {
	Listen(addr string) error

	Accept() (Channel, net.Addr, error)

	Close() error
}

type ChannelFactory func() Channel

type ListenerFactory func() Listener

var (
	channels   = make(map[ChannelType]ChannelFactory)
	listeners  = make(map[ChannelType]ListenerFactory)
	registryMu sync.RWMutex
)

func Register(t ChannelType, cf ChannelFactory, lf ListenerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	channels[t] = cf
	listeners[t] = lf
}

func NewChannel(t ChannelType) Channel {
	registryMu.RLock()
	f := channels[t]
	registryMu.RUnlock()
	if f != nil {
		return f()
	}
	return nil
}

func NewListener(t ChannelType) Listener {
	registryMu.RLock()
	f := listeners[t]
	registryMu.RUnlock()
	if f != nil {
		return f()
	}
	return nil
}

func RegisteredChannels() []ChannelType {
	registryMu.RLock()
	types := make([]ChannelType, 0, len(channels))
	for t := range channels {
		types = append(types, t)
	}
	registryMu.RUnlock()
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}
