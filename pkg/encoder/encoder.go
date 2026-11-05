package encoder

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	MaxFrameSize        = 1400
	HeaderSize          = 8
	MaxDecompressedSize = 100 * 1024 * 1024
)

var (
	ErrFrameTooLarge = errors.New("frame exceeds maximum size")
	ErrBadCRC        = errors.New("frame CRC mismatch")
)

type Frame struct {
	Seq     uint32
	Total   uint32
	Payload []byte
}

func Encode(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}
	w.Close()
	return buf.Bytes(), nil
}

func Decode(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	defer r.Close()
	limited := io.LimitReader(r, MaxDecompressedSize)
	return io.ReadAll(limited)
}

func SplitIntoFrames(data []byte, maxPayloadSize int) ([]Frame, error) {
	if maxPayloadSize <= 0 {
		maxPayloadSize = MaxFrameSize - HeaderSize
	}
	totalFrames := (len(data) + maxPayloadSize - 1) / maxPayloadSize
	if totalFrames > 0xFFFFFFFF {
		return nil, fmt.Errorf("data too large: %d frames needed", totalFrames)
	}
	frames := make([]Frame, 0, totalFrames)
	for i := 0; i < totalFrames; i++ {
		start := i * maxPayloadSize
		end := start + maxPayloadSize
		if end > len(data) {
			end = len(data)
		}
		frames = append(frames, Frame{
			Seq:     uint32(i),
			Total:   uint32(totalFrames),
			Payload: data[start:end],
		})
	}
	return frames, nil
}

func MarshalFrame(f Frame) []byte {
	buf := make([]byte, HeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:4], f.Seq)
	binary.BigEndian.PutUint32(buf[4:8], f.Total)
	copy(buf[HeaderSize:], f.Payload)
	return buf
}

func UnmarshalFrame(data []byte) (Frame, error) {
	if len(data) < HeaderSize {
		return Frame{}, fmt.Errorf("frame too short: %d bytes", len(data))
	}
	return Frame{
		Seq:     binary.BigEndian.Uint32(data[0:4]),
		Total:   binary.BigEndian.Uint32(data[4:8]),
		Payload: data[HeaderSize:],
	}, nil
}

func ReassembleFrames(frames []Frame) ([]byte, error) {
	if len(frames) == 0 {
		return nil, errors.New("no frames")
	}
	total := frames[0].Total
	if uint32(len(frames)) != total {
		return nil, fmt.Errorf("missing frames: got %d, expected %d", len(frames), total)
	}
	var buf bytes.Buffer
	seen := make([]bool, total)
	for _, f := range frames {
		if f.Seq >= total {
			return nil, fmt.Errorf("sequence out of range: %d >= %d", f.Seq, total)
		}
		if seen[f.Seq] {
			return nil, fmt.Errorf("duplicate frame seq %d", f.Seq)
		}
		seen[f.Seq] = true
	}
	for seq := uint32(0); seq < total; seq++ {
		for _, f := range frames {
			if f.Seq == seq {
				buf.Write(f.Payload)
				break
			}
		}
	}
	return buf.Bytes(), nil
}

func Checksum(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}
