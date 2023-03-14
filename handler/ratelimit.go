package handler

import (
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

func NewRateLimiter() *RateLimiter {
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

func (limiter *RateLimiter) Limit(peer string) {
	limiter.mutex.Lock()
	val, ok := limiter.peers[peer]
	limiter.mutex.Unlock()
	if ok {
		time.Sleep(time.Until(val))
	}

	limiter.mutex.Lock()
	limiter.peers[peer] = time.Now().Add(defaultLifeSpan)
	limiter.mutex.Unlock()
}

func (limiter *RateLimiter) LimitDuration(peer string, t time.Duration) {
	limiter.mutex.Lock()
	val, ok := limiter.peers[peer]
	limiter.mutex.Unlock()
	if ok {
		time.Sleep(time.Until(val))
	}

	limiter.mutex.Lock()
	limiter.peers[peer] = time.Now().Add(t)
	limiter.mutex.Unlock()
}
