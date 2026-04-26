package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type bucket struct {
	mu       sync.Mutex
	tokens   float64
	lastFill time.Time
	rate     float64 // tokens per second
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.rate {
		b.tokens = b.rate // burst cap == rps
	}
	b.lastFill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RateLimit returns a middleware that limits each remote IP to rps
// requests per second using a token bucket. Excess requests get 429.
func RateLimit(rps int) func(http.Handler) http.Handler {
	var buckets sync.Map
	rate := float64(rps)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			val, _ := buckets.LoadOrStore(ip, &bucket{
				tokens:   rate,
				lastFill: time.Now(),
				rate:     rate,
			})
			if !val.(*bucket).allow() {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
