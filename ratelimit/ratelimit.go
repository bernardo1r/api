package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

const (
	defaultLifeSpan    = time.Second * 1
	defaultGarbageTime = time.Second * 10
)

type RateLimiter struct {
	close chan struct{}
	peers map[string]time.Time
	mutex sync.Mutex
}

func (limiter *RateLimiter) update() {
	ticker := time.NewTicker(defaultGarbageTime)
	defer ticker.Stop()
	for {
		select {
		case <-limiter.close:
			return

		case <-ticker.C:
			now := time.Now()
			limiter.mutex.Lock()
			for k, v := range limiter.peers {
				if now.After(v) {
					delete(limiter.peers, k)
				}
			}
			limiter.mutex.Unlock()
		}
	}
}

func New() *RateLimiter {
	limiter := &RateLimiter{
		close: make(chan struct{}),
		peers: make(map[string]time.Time),
	}
	go limiter.update()
	return limiter
}

func (limiter *RateLimiter) Close() {
	limiter.close <- struct{}{}
}

func (limiter *RateLimiter) Limit(peer string) bool {
	limiter.mutex.Lock()
	value, ok := limiter.peers[peer]
	var ret bool
	if !ok || time.Now().After(value) {
		ret = true
		limiter.peers[peer] = time.Now().Add(defaultGarbageTime)
	} else {
		ret = false
	}
	fmt.Println(limiter.peers[peer])
	limiter.mutex.Unlock()

	return ret
}

func (limiter *RateLimiter) LimitDuration(peer string, t time.Duration) bool {
	limiter.mutex.Lock()
	value, ok := limiter.peers[peer]
	var ret bool
	if !ok || time.Now().After(value) {
		ret = true
		limiter.peers[peer] = time.Now().Add(t)
	} else {
		ret = false
	}
	limiter.mutex.Unlock()

	return ret
}
