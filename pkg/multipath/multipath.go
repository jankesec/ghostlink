package multipath

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/byjanke/ghostlink/pkg/channel"
	"github.com/byjanke/ghostlink/pkg/crypto"
	"github.com/byjanke/ghostlink/pkg/encoder"
)

type MultipathSender struct {
	channels []channel.Channel
	sessions []*crypto.Session
	fecData  int
	fecTotal int
	mu       sync.Mutex
}

func NewMultipathSender(dataShards, totalShards int) *MultipathSender {
	return &MultipathSender{
		fecData:  dataShards,
		fecTotal: totalShards,
	}
}

func (m *MultipathSender) AddPath(ch channel.Channel, ses *crypto.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.channels = append(m.channels, ch)
	m.sessions = append(m.sessions, ses)
}

func (m *MultipathSender) PathCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.channels)
}

func (m *MultipathSender) Send(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.channels) == 0 {
		return fmt.Errorf("no channels available")
	}

	fecBlock, err := encoder.XOREncode(data, m.fecData, m.fecTotal)
	if err != nil {
		fecBlock = &encoder.FECBlock{
			DataShards: 1,
			TotalShards: 1,
			ShardSize: len(data),
			Shards:    [][]byte{data},
			ParityShards: [][]byte{},
		}
	}

	allShards := append(fecBlock.Shards, fecBlock.ParityShards...)

	var wg sync.WaitGroup
	var errorCount int32
	numChannels := len(m.channels)

	for i, shard := range allShards {
		idx := i % numChannels
		ch := m.channels[idx]
		ses := m.sessions[idx]

		wg.Add(1)
		go func(shardData []byte, ch channel.Channel, ses *crypto.Session) {
			defer wg.Done()
			payload := encoder.MarshalFECBlock(&encoder.FECBlock{
				DataShards:  fecBlock.DataShards,
				TotalShards: len(allShards),
				ShardSize:  len(shardData),
				Shards:     [][]byte{shardData},
				ParityShards: [][]byte{},
			})
			encoded, _ := encoder.Encode(payload)

			var finalData []byte
			if ses != nil {
				var encErr error
				finalData, encErr = ses.Encrypt(encoded)
				if encErr != nil {
					atomic.AddInt32(&errorCount, 1)
					return
				}
			} else {
				finalData = encoded
			}

			if sendErr := ch.Send(finalData); sendErr != nil {
				atomic.AddInt32(&errorCount, 1)
			}
		}(shard, ch, ses)

		time.Sleep(5 * time.Millisecond)
	}

	wg.Wait()

	if int(errorCount) >= len(m.channels) {
		return fmt.Errorf("all channels failed")
	}

	return nil
}

var _ = time.Now
