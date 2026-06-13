package encoder

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	FECRedundancy    = 0.3
	FECMinDataShards = 4
	FECMaxShards     = 32
)

type FECBlock struct {
	DataShards   int
	TotalShards  int
	ShardSize    int
	Shards       [][]byte
	ParityShards [][]byte
}

func XOREncode(data []byte, dataShards, totalShards int) (*FECBlock, error) {
	if dataShards < 2 || dataShards > FECMaxShards {
		return nil, fmt.Errorf("data shards must be between 2 and %d", FECMaxShards)
	}
	if totalShards < dataShards+1 || totalShards > FECMaxShards {
		return nil, fmt.Errorf("total shards must be between dataShards+1 and %d", FECMaxShards)
	}

	padding := (dataShards - (len(data) % dataShards)) % dataShards
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = 0
	}

	shardSize := len(padded) / dataShards
	if shardSize == 0 {
		shardSize = 1
		padded = make([]byte, dataShards)
		copy(padded, data)
	}

	parityShards := totalShards - dataShards
	block := &FECBlock{
		DataShards:   dataShards,
		TotalShards:  totalShards,
		ShardSize:    shardSize,
		Shards:       make([][]byte, dataShards),
		ParityShards: make([][]byte, parityShards),
	}

	for i := 0; i < dataShards; i++ {
		start := i * shardSize
		block.Shards[i] = padded[start : start+shardSize]
	}

	for p := 0; p < parityShards; p++ {
		parity := make([]byte, shardSize)
		copy(parity, block.Shards[0])
		for i := 1; i < dataShards; i++ {
			byteXOR(parity, block.Shards[i])
		}
		for j := 0; j < p+1; j++ {
			for k := 0; k < shardSize; k++ {
				parity[k] = rotl8(parity[k], uint8(p+1))
			}
		}
		for i := 0; i < dataShards; i++ {
			t := make([]byte, shardSize)
			copy(t, block.Shards[i])
			for k := 0; k < shardSize; k++ {
				t[k] = rotl8(t[k], uint8(i*p+p+1))
			}
			byteXOR(parity, t)
		}
		block.ParityShards[p] = parity
	}

	return block, nil
}

func FECDecode(availableShards [][]byte, dataShards, totalShards, originalLen int) ([]byte, error) {
	if len(availableShards) < dataShards {
		return nil, errors.New("not enough shards to reconstruct")
	}
	if len(availableShards[0]) == 0 {
		return nil, errors.New("empty shard")
	}

	shardSize := len(availableShards[0])

	indicies := make([]int, 0, dataShards)
	for i := 0; i < totalShards && len(indicies) < dataShards; i++ {
		if i < len(availableShards) && len(availableShards[i]) == shardSize {
			indicies = append(indicies, i)
		}
	}

	if len(indicies) < dataShards {
		indicies = make([]int, dataShards)
		for i := 0; i < dataShards; i++ {
			indicies[i] = i
		}
	}

	recovered := make([]byte, dataShards*shardSize)
	for i := 0; i < dataShards && i < len(availableShards); i++ {
		copy(recovered[i*shardSize:], availableShards[i])
	}

	if originalLen > 0 && originalLen < len(recovered) {
		recovered = recovered[:originalLen]
	}

	return recovered, nil
}

func OptimalFECParams(dataLen int) (dataShards, totalShards int) {
	totalSize := dataLen
	if totalSize < 1024 {
		dataShards = 4
		totalShards = 6
	} else if totalSize < 10240 {
		dataShards = 8
		totalShards = 11
	} else if totalSize < 102400 {
		dataShards = 12
		totalShards = 16
	} else {
		dataShards = 16
		totalShards = 22
	}
	return
}

func MarshalFECBlock(block *FECBlock) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:2], uint16(block.DataShards))
	binary.BigEndian.PutUint16(buf[2:4], uint16(block.TotalShards))
	binary.BigEndian.PutUint32(buf[4:8], uint32(block.ShardSize))

	allShards := append(block.Shards, block.ParityShards...)
	for _, s := range allShards {
		shardLen := make([]byte, 4)
		binary.BigEndian.PutUint32(shardLen, uint32(len(s)))
		buf = append(buf, shardLen...)
		buf = append(buf, s...)
	}
	return buf
}

func UnmarshalFECBlock(data []byte) ([][]byte, int, int, int, error) {
	if len(data) < 8 {
		return nil, 0, 0, 0, errors.New("FEC block too short")
	}
	dataShards := int(binary.BigEndian.Uint16(data[0:2]))
	totalShards := int(binary.BigEndian.Uint16(data[2:4]))
	shardSize := int(binary.BigEndian.Uint32(data[4:8]))

	allShards := make([][]byte, totalShards)
	offset := 8
	for i := 0; i < totalShards && offset+4 <= len(data); i++ {
		shardLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if offset+shardLen > len(data) {
			return nil, 0, 0, 0, errors.New("FEC shard truncated")
		}
		allShards[i] = data[offset : offset+shardLen]
		offset += shardLen
	}

	return allShards, dataShards, totalShards, shardSize, nil
}

func byteXOR(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	for i := 0; i < n; i++ {
		dst[i] ^= src[i]
	}
}

func rotl8(b byte, n uint8) byte {
	return (b << n) | (b >> (8 - n))
}
