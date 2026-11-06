// Package demo implements Ghostlink's deterministic, network-free pipeline demo.
package demo

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	cryptopkg "github.com/byjanke/ghostlink/pkg/crypto"
	"github.com/byjanke/ghostlink/pkg/encoder"
	"github.com/byjanke/ghostlink/pkg/protocol"
)

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiGreen = "\x1b[32m"
	ansiCyan  = "\x1b[36m"
)

type validationCheck struct {
	stage       string
	observation string
}

func paint(enabled bool, code, value string) string {
	if !enabled {
		return value
	}
	return code + value + ansiReset
}

func printBoxLine(out io.Writer, color bool, code, text string) {
	padding := 74 - utf8.RuneCountInString(text)
	if padding < 0 {
		padding = 0
	}
	fmt.Fprintf(out, "│  %s%s  │\n", paint(color, code, text), strings.Repeat(" ", padding))
}

// Run executes and renders the safe offline pipeline validation.
func Run(out io.Writer, color bool) error {
	payload := []byte(strings.Repeat("authorized-lab telemetry record\n", 24))
	originalDigest := sha256.Sum256(payload)
	checks := make([]validationCheck, 0, 6)

	senderPrivate, senderPublic, err := cryptopkg.GenerateKeyExchange()
	if err != nil {
		return fmt.Errorf("generate sender key: %w", err)
	}
	receiverPrivate, receiverPublic, err := cryptopkg.GenerateKeyExchange()
	if err != nil {
		return fmt.Errorf("generate receiver key: %w", err)
	}
	senderShared, err := cryptopkg.CompleteKeyExchange(senderPrivate, receiverPublic)
	if err != nil {
		return fmt.Errorf("complete sender exchange: %w", err)
	}
	receiverShared, err := cryptopkg.CompleteKeyExchange(receiverPrivate, senderPublic)
	if err != nil {
		return fmt.Errorf("complete receiver exchange: %w", err)
	}
	senderKey := cryptopkg.DeriveKey(senderShared, "ghostlink-local-demo")
	receiverKey := cryptopkg.DeriveKey(receiverShared, "ghostlink-local-demo")
	if !bytes.Equal(senderKey, receiverKey) {
		return fmt.Errorf("derived session keys do not match")
	}
	checks = append(checks, validationCheck{"Key agreement", "P-256 peers derived the same 32-byte session key"})

	senderSession, err := cryptopkg.NewSession(senderKey)
	if err != nil {
		return fmt.Errorf("create sender session: %w", err)
	}
	receiverSession, err := cryptopkg.NewSession(receiverKey)
	if err != nil {
		return fmt.Errorf("create receiver session: %w", err)
	}

	compressed, err := encoder.Encode(payload)
	if err != nil {
		return fmt.Errorf("compress payload: %w", err)
	}
	checks = append(checks, validationCheck{
		"Compression",
		fmt.Sprintf("zlib reduced %d synthetic bytes to %d bytes", len(payload), len(compressed)),
	})

	dataShards, totalShards := encoder.OptimalFECParams(len(compressed))
	fecBlock, err := encoder.XOREncode(compressed, dataShards, totalShards)
	if err != nil {
		return fmt.Errorf("encode parity layout: %w", err)
	}
	fecBytes := encoder.MarshalFECBlock(fecBlock)
	checks = append(checks, validationCheck{
		"Parity layout",
		fmt.Sprintf("%d data shards and %d XOR parity shards encoded", dataShards, totalShards-dataShards),
	})

	frames, err := encoder.SplitIntoFrames(fecBytes, 48)
	if err != nil {
		return fmt.Errorf("split frames: %w", err)
	}
	receivedFrames := make([]encoder.Frame, 0, len(frames))
	for _, frame := range frames {
		wireMessage, err := protocol.MarshalBinary(protocol.Message{
			Type:     protocol.MsgExfilChunk,
			StreamID: 1,
			Payload:  encoder.MarshalFrame(frame),
		})
		if err != nil {
			return fmt.Errorf("encode protocol message: %w", err)
		}
		ciphertext, err := senderSession.Encrypt(wireMessage)
		if err != nil {
			return fmt.Errorf("encrypt frame: %w", err)
		}
		plaintext, err := receiverSession.Decrypt(ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt frame: %w", err)
		}
		message, err := protocol.Unmarshal(plaintext)
		if err != nil {
			return fmt.Errorf("decode protocol message: %w", err)
		}
		decodedFrame, err := encoder.UnmarshalFrame(message.Payload)
		if err != nil {
			return fmt.Errorf("decode frame: %w", err)
		}
		receivedFrames = append(receivedFrames, decodedFrame)
	}
	checks = append(checks, validationCheck{
		"Framing",
		fmt.Sprintf("protocol v%d carried %d sequenced frames", protocol.ProtocolVersion, len(frames)),
	})
	checks = append(checks, validationCheck{
		"Encryption",
		fmt.Sprintf("AES-256-GCM authenticated all %d frames", len(frames)),
	})

	reassembled, err := encoder.ReassembleFrames(receivedFrames)
	if err != nil {
		return fmt.Errorf("reassemble frames: %w", err)
	}
	shards, decodedDataShards, decodedTotalShards, _, err := encoder.UnmarshalFECBlock(reassembled)
	if err != nil {
		return fmt.Errorf("decode parity layout: %w", err)
	}
	recoveredCompressed, err := encoder.FECDecode(
		shards,
		decodedDataShards,
		decodedTotalShards,
		len(compressed),
	)
	if err != nil {
		return fmt.Errorf("recover compressed payload: %w", err)
	}
	recovered, err := encoder.Decode(recoveredCompressed)
	if err != nil {
		return fmt.Errorf("decompress payload: %w", err)
	}
	recoveredDigest := sha256.Sum256(recovered)
	if !bytes.Equal(payload, recovered) || recoveredDigest != originalDigest {
		return fmt.Errorf("end-to-end integrity check failed")
	}
	checks = append(checks, validationCheck{
		"Integrity",
		fmt.Sprintf("SHA-256 %x matched after local round trip", recoveredDigest[:6]),
	})

	fmt.Fprintln(out, "┌──────────────────────────────────────────────────────────────────────────────┐")
	printBoxLine(out, color, ansiBold+ansiCyan, "GHOSTLINK / SAFE OFFLINE ROUND TRIP")
	printBoxLine(out, color, "", "QUESTION  Can Ghostlink protect and reconstruct one synthetic lab record?")
	printBoxLine(out, color, ansiGreen+ansiBold, "BOUNDARY  0 sockets · 0 targets · 0 external services")
	fmt.Fprintln(out, "└──────────────────────────────────────────────────────────────────────────────┘")
	fmt.Fprintln(out)
	fmt.Fprintln(out, paint(color, ansiBold, "INPUT"))
	fmt.Fprintf(out, "Synthetic record   %d bytes   SHA-256 %x…\n", len(payload), originalDigest[:6])
	fmt.Fprintln(out, `"authorized-lab telemetry record" (repeated test data)`)
	fmt.Fprintln(out)
	fmt.Fprintln(out, paint(color, ansiBold, "LOCAL DATA FLOW"))
	fmt.Fprintln(out, "INPUT → COMPRESS → SHARD → FRAME → ENCRYPT → DECRYPT → REBUILD → VERIFY")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%-20s %-9s %s\n", "STEP", "RESULT", "EVIDENCE")
	fmt.Fprintln(out, strings.Repeat("─", 78))
	for _, check := range checks {
		fmt.Fprintf(out, "%-20s %-9s %s\n", check.stage, paint(color, ansiGreen+ansiBold, "PASS"), check.observation)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, paint(color, ansiBold, "VERIFIED OUTPUT"))
	fmt.Fprintf(out, "Recovered record   %d bytes   SHA-256 %x…   EXACT MATCH\n", len(recovered), recoveredDigest[:6])
	fmt.Fprintf(out, "%s  %d/%d checks passed; input and output are identical.\n", paint(color, ansiGreen+ansiBold, "PASS"), len(checks), len(checks))
	fmt.Fprintln(out)
	fmt.Fprintln(out, paint(color, ansiDim, "PROVES: the local crypto/framing pipeline preserves synthetic data."))
	fmt.Fprintln(out, paint(color, ansiDim, "DOES NOT PROVE: network reliability, stealth, or real-world deployment safety."))
	return nil
}
