package channel

import (
	"fmt"
	"sync"
	"time"
)

type CanaryState int

const (
	CanaryOK      CanaryState = 0
	CanaryDegrade CanaryState = 1
	CanarySilent  CanaryState = 2
	CanaryDead    CanaryState = 3
)

type CanaryConfig struct {
	CheckInterval   time.Duration
	FailureCount    int
	SilenceDuration time.Duration
	SelfDestruct    bool
	OnAlert         func(state CanaryState)
}

type ChannelCanary struct {
	cfg      CanaryConfig
	ch       Channel
	state    CanaryState
	failures int
	mu       sync.Mutex
	stopCh   chan struct{}
}

func NewChannelCanary(cfg CanaryConfig) *ChannelCanary {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 10 * time.Second
	}
	if cfg.FailureCount <= 0 {
		cfg.FailureCount = 5
	}
	return &ChannelCanary{
		cfg:    cfg,
		state:  CanaryOK,
		stopCh: make(chan struct{}),
	}
}

func (c *ChannelCanary) Attach(ch Channel) {
	c.mu.Lock()
	c.ch = ch
	c.mu.Unlock()
}

func (c *ChannelCanary) State() CanaryState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *ChannelCanary) Start() {
	go func() {
		ticker := time.NewTicker(c.cfg.CheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.check()
			}
		}
	}()
}

func (c *ChannelCanary) Stop() {
	close(c.stopCh)
}

func (c *ChannelCanary) RecordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	if c.state == CanaryDegrade {
		c.state = CanaryOK
		c.alert(CanaryOK)
	}
}

func (c *ChannelCanary) RecordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures++
	if c.failures >= c.cfg.FailureCount {
		switch c.state {
		case CanaryOK:
			c.state = CanaryDegrade
			go c.alert(CanaryDegrade)
		case CanaryDegrade:
			c.state = CanarySilent
			go c.alert(CanarySilent)
		case CanarySilent:
			c.state = CanaryDead
			go c.alert(CanaryDead)
		}
	}
}

func (c *ChannelCanary) check() {
	c.mu.Lock()
	ch := c.ch
	c.mu.Unlock()

	if ch == nil {
		return
	}

	ping := make([]byte, 1)
	ping[0] = 0xFF
	if err := ch.Send(ping); err != nil {
		c.RecordFailure()
	} else {
		c.RecordSuccess()
	}
}

func (c *ChannelCanary) alert(state CanaryState) {
	if c.cfg.OnAlert != nil {
		c.cfg.OnAlert(state)
	}

	switch state {
	case CanaryDegrade:
		fmt.Println("[canary] channel degraded — switching to backup")
	case CanarySilent:
		fmt.Printf("[canary] channel silent — silencing for %v\n", c.cfg.SilenceDuration)
		if c.cfg.SilenceDuration > 0 {
			time.Sleep(c.cfg.SilenceDuration)
		}
		c.mu.Lock()
		if c.state == CanarySilent {
			c.state = CanaryDegrade
		}
		c.mu.Unlock()
	case CanaryDead:
		fmt.Println("[canary] channel dead — initiating self-destruct")
	}
}
