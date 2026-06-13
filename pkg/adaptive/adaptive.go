package adaptive

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"

	"github.com/byjanke/ghostlink/pkg/channel"
)

type ChannelScore struct {
	Type       channel.ChannelType
	Score      float64
	LastUsed   time.Time
	ErrorCount int
}

type EntropyAnalyzer struct {
	mu              sync.Mutex
	scores          map[channel.ChannelType]*ChannelScore
	history         []channel.ChannelType
	historySize     int
	diversityWeight float64
	latencyWeight   float64
	errorPenalty    float64
}

func NewEntropyAnalyzer() *EntropyAnalyzer {
	return &EntropyAnalyzer{
		scores:          make(map[channel.ChannelType]*ChannelScore),
		historySize:     50,
		diversityWeight: 0.3,
		latencyWeight:   0.4,
		errorPenalty:    0.3,
	}
}

func (ea *EntropyAnalyzer) RegisterChannel(ch channel.Channel) {
	info := ch.Info()
	ea.mu.Lock()
	defer ea.mu.Unlock()
	if _, exists := ea.scores[info.Type]; !exists {
		ea.scores[info.Type] = &ChannelScore{
			Type:  info.Type,
			Score: info.Capability,
		}
	}
}

func (ea *EntropyAnalyzer) UpdateScore(ct channel.ChannelType, success bool, latency time.Duration) {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	cs, exists := ea.scores[ct]
	if !exists {
		return
	}

	cs.LastUsed = time.Now()

	if success {
		latencyScore := 1.0
		if latency > 500*time.Millisecond {
			latencyScore = 0.3
		} else if latency > 200*time.Millisecond {
			latencyScore = 0.6
		} else if latency > 50*time.Millisecond {
			latencyScore = 0.8
		}

		cs.Score = cs.Score*0.7 + latencyScore*0.3
		cs.ErrorCount = 0
	} else {
		cs.ErrorCount++
		penalty := math.Pow(ea.errorPenalty, float64(cs.ErrorCount))
		cs.Score = cs.Score * (1 - penalty)
	}
}

func (ea *EntropyAnalyzer) Select() channel.ChannelType {
	ea.mu.Lock()
	defer ea.mu.Unlock()

	if len(ea.scores) == 0 {
		return channel.HTTPChannel
	}

	var bestType channel.ChannelType
	bestScore := -1.0

	for ct, cs := range ea.scores {
		score := cs.Score
		diversityBonus := ea.calculateDiversityBonusLocked(ct)
		score += diversityBonus * ea.diversityWeight

		if score > bestScore {
			bestScore = score
			bestType = ct
		}
	}

	if len(ea.history) >= ea.historySize {
		ea.history = ea.history[1:]
	}
	ea.history = append(ea.history, bestType)

	return bestType
}

func (ea *EntropyAnalyzer) calculateDiversityBonusLocked(ct channel.ChannelType) float64 {
	recentCount := 0
	windowSize := 20
	start := len(ea.history) - windowSize
	if start < 0 {
		start = 0
	}
	for _, h := range ea.history[start:] {
		if h == ct {
			recentCount++
		}
	}
	if recentCount == 0 {
		return 1.0
	}
	return 1.0 - float64(recentCount)/float64(windowSize)
}

func (ea *EntropyAnalyzer) GetScores() map[channel.ChannelType]float64 {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	result := make(map[channel.ChannelType]float64)
	for ct, cs := range ea.scores {
		result[ct] = cs.Score
	}
	return result
}

func (ea *EntropyAnalyzer) RandomizeSelection(types []channel.ChannelType) channel.ChannelType {
	if len(types) == 0 {
		return channel.HTTPChannel
	}
	var b [8]byte
	crand.Read(b[:])
	idx := binary.LittleEndian.Uint64(b[:]) % uint64(len(types))
	return types[idx]
}
