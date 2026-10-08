package relay

import (
	"context"
	"net"
	"sync"

	"golang.org/x/time/rate"
)

// Per-connection bandwidth limiting.
//
// The limit is applied at the listener, so it covers every DERP byte the
// connection carries, in both directions: client traffic, TLS handshake and
// mesh links alike. It is deliberately per connection: it bounds how much one
// peer can take from the relay, not the relay's total capacity. A global cap
// would need fairness across connections and is not what an operator asking
// for "a bandwidth limit" on a node means.

// limitedListener wraps a net.Listener so that every accepted connection is
// rate limited.
type limitedListener struct {
	net.Listener
	limit rate.Limit
	burst int
}

func newLimitedListener(ln net.Listener, limit rate.Limit, burst int) net.Listener {
	return &limitedListener{Listener: ln, limit: limit, burst: burst}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newLimitedConn(conn, rate.NewLimiter(l.limit, l.burst)), nil
}

// limitedConn applies one token bucket to both directions of a connection.
//
// The bucket is shared between reads and writes on purpose: the operator's
// number is a per-connection throughput bound, and giving each direction its
// own bucket would double it.
type limitedConn struct {
	net.Conn
	limiter *rate.Limiter

	// ctx is cancelled by Close, so a caller blocked waiting for tokens
	// does not have to wait out the limit after the peer left.
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func newLimitedConn(conn net.Conn, limiter *rate.Limiter) *limitedConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &limitedConn{Conn: conn, limiter: limiter, ctx: ctx, cancel: cancel}
}

// Read reserves tokens for at most len(p) bytes, then reads.
//
// The reservation happens before the read, so it over-reserves when the peer
// sends less than the buffer fits. That is the fail-closed direction: it can
// only make a connection slower than its configured limit, never faster.
func (c *limitedConn) Read(p []byte) (int, error) {
	if err := c.reserve(len(p)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// Write reserves tokens for exactly len(p) bytes, then writes.
func (c *limitedConn) Write(p []byte) (int, error) {
	if err := c.reserve(len(p)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

// Close cancels pending token waits and closes the underlying connection.
func (c *limitedConn) Close() error {
	c.once.Do(c.cancel)
	return c.Conn.Close()
}

// reserve waits for n bytes' worth of tokens. n is clamped to the bucket
// size: rate.Limiter.WaitN refuses n greater than the burst, and the caller
// only needs the wait to be bounded, not exact.
func (c *limitedConn) reserve(n int) error {
	if n <= 0 {
		return nil
	}
	if n > c.limiter.Burst() {
		n = c.limiter.Burst()
	}
	return c.limiter.WaitN(c.ctx, n)
}
