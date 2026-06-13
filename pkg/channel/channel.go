package channel

import "net"

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
	channels  = make(map[ChannelType]ChannelFactory)
	listeners = make(map[ChannelType]ListenerFactory)
)

func Register(t ChannelType, cf ChannelFactory, lf ListenerFactory) {
	channels[t] = cf
	listeners[t] = lf
}

func NewChannel(t ChannelType) Channel {
	if f, ok := channels[t]; ok {
		return f()
	}
	return nil
}

func NewListener(t ChannelType) Listener {
	if f, ok := listeners[t]; ok {
		return f()
	}
	return nil
}

func RegisteredChannels() []ChannelType {
	var types []ChannelType
	for t := range channels {
		types = append(types, t)
	}
	return types
}
