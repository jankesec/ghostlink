// Package operator provides read-only operator discovery and environment checks.
package operator

import (
	"fmt"
	"runtime"
	"sort"

	"github.com/byjanke/ghostlink/pkg/channel"
)

// Transport describes the operating requirements of a registered transport.
type Transport struct {
	ID          channel.ChannelType `json:"id"`
	Class       string              `json:"class"`
	Requirement string              `json:"requirement"`
	Stability   string              `json:"stability"`
}

var transportMetadata = map[channel.ChannelType]Transport{
	channel.DNSChannel:        {Class: "user-space", Requirement: "dedicated loopback/lab port", Stability: "stable"},
	channel.DoHChannel:        {Class: "user-space", Requirement: "explicit HTTP endpoint", Stability: "stable"},
	channel.HTTPChannel:       {Class: "user-space", Requirement: "explicit listener", Stability: "stable"},
	channel.WebSocketChannel:  {Class: "user-space", Requirement: "explicit listener", Stability: "stable"},
	channel.ICMPChannel:       {Class: "raw-socket", Requirement: "OS privileges", Stability: "experimental"},
	channel.TCPISNChannel:     {Class: "raw-socket", Requirement: "OS privileges", Stability: "experimental"},
	channel.IPIDChannel:       {Class: "raw-socket", Requirement: "IPv4 and OS privileges", Stability: "experimental"},
	channel.TimingChannel:     {Class: "signal", Requirement: "controlled low-jitter lab", Stability: "experimental"},
	channel.PacketSizeChannel: {Class: "signal", Requirement: "controlled MTU/lab path", Stability: "experimental"},
}

// Transports returns a deterministic inventory without opening sockets.
func Transports() []Transport {
	registered := channel.RegisteredChannels()
	result := make([]Transport, 0, len(registered))
	for _, id := range registered {
		item, ok := transportMetadata[id]
		if !ok {
			item = Transport{Class: "unknown", Requirement: "review implementation", Stability: "experimental"}
		}
		item.ID = id
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// ValidateCatalog ensures every compiled transport has operator metadata.
func ValidateCatalog() error {
	for _, id := range channel.RegisteredChannels() {
		if _, ok := transportMetadata[id]; !ok {
			return fmt.Errorf("transport %q has no operator metadata", id)
		}
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return fmt.Errorf("%s is not a release-tested operating system", runtime.GOOS)
	}
	return nil
}
