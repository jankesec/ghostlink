package beacon

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

type Profile string

const (
	ProfileLowSlow   Profile = "low_slow"
	ProfileOfficeDay Profile = "office_day"
	ProfileNight     Profile = "night"
	ProfileBurst     Profile = "burst"
	ProfileRandom    Profile = "random"
)

type Jitter struct {
	profile      Profile
	baseInterval time.Duration
	jitterPct    float64
	minSleep     time.Duration
	maxSleep     time.Duration
	burstSize    int
	burstPause   time.Duration
	burstCount   int
}

func New(profile Profile) *Jitter {
	j := &Jitter{profile: profile}
	switch profile {
	case ProfileLowSlow:
		j.baseInterval = 5 * time.Minute
		j.jitterPct = 0.5
		j.minSleep = 2 * time.Minute
		j.maxSleep = 10 * time.Minute
	case ProfileOfficeDay:
		j.baseInterval = 30 * time.Second
		j.jitterPct = 0.4
		j.minSleep = 10 * time.Second
		j.maxSleep = 90 * time.Second
	case ProfileNight:
		j.baseInterval = 15 * time.Minute
		j.jitterPct = 0.6
		j.minSleep = 5 * time.Minute
		j.maxSleep = 30 * time.Minute
	case ProfileBurst:
		j.baseInterval = 2 * time.Second
		j.jitterPct = 0.3
		j.minSleep = 500 * time.Millisecond
		j.maxSleep = 5 * time.Second
		j.burstSize = 5
		j.burstPause = 2 * time.Minute
	case ProfileRandom:
		j.baseInterval = 60 * time.Second
		j.jitterPct = 0.9
		j.minSleep = 5 * time.Second
		j.maxSleep = 5 * time.Minute
	default:
		j.baseInterval = 30 * time.Second
		j.jitterPct = 0.3
		j.minSleep = 10 * time.Second
		j.maxSleep = 60 * time.Second
	}
	return j
}

func (j *Jitter) Wait() {
	d := j.NextInterval()
	time.Sleep(d)
}

func (j *Jitter) NextInterval() time.Duration {
	if j.profile == ProfileBurst && j.burstSize > 0 {
		j.burstCount++
		if j.burstCount >= j.burstSize {
			j.burstCount = 0
			return j.burstPause + j.randomDuration(j.burstPause/2)
		}
	}

	if j.profile == ProfileOfficeDay && !isWorkHours() {
		return j.maxSleep * 3
	}

	jitter := j.randomDuration(time.Duration(float64(j.baseInterval) * j.jitterPct))
	d := j.baseInterval + jitter
	if d < j.minSleep {
		d = j.minSleep
	}
	if d > j.maxSleep {
		d = j.maxSleep
	}
	return d
}

func (j *Jitter) randomDuration(maxJitter time.Duration) time.Duration {
	var b [8]byte
	crand.Read(b[:])
	n := binary.LittleEndian.Uint64(b[:])
	f := float64(n) / float64(math.MaxUint64)
	return time.Duration(f*float64(maxJitter)*2 - float64(maxJitter))
}

func isWorkHours() bool {
	h := time.Now().Hour()
	wd := time.Now().Weekday()
	if wd == time.Saturday || wd == time.Sunday {
		return false
	}
	return h >= 8 && h < 18
}

func ParseProfile(s string) Profile {
	switch s {
	case "low_slow", "lowslow":
		return ProfileLowSlow
	case "office_day", "office":
		return ProfileOfficeDay
	case "night":
		return ProfileNight
	case "burst":
		return ProfileBurst
	case "random":
		return ProfileRandom
	default:
		return ProfileOfficeDay
	}
}
