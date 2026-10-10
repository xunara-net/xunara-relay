package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// 所有 TCP 都被追踪，包括初始不限速的连接；热更不要求客户端重新连接。
type limitedListener struct {
	net.Listener
	runtime *runtimeControl
}

func (l *limitedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.runtime.track(conn), nil
}

// 双向流量共用同一令牌桶，避免上传和下载各获得一份额度。
type limitedConn struct {
	net.Conn
	limiter *rate.Limiter
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
	onClose func()

	mu            sync.Mutex
	waitContext   context.Context
	cancelWait    context.CancelFunc
	readDeadline  time.Time
	writeDeadline time.Time
	readMutex     sync.Mutex
	readPending   []byte
	readError     error
}

func newLimitedConn(conn net.Conn, limiter *rate.Limiter) *limitedConn {
	ctx, cancel := context.WithCancel(context.Background())
	waitContext, cancelWait := context.WithCancel(ctx)
	return &limitedConn{Conn: conn, limiter: limiter, ctx: ctx, cancel: cancel, waitContext: waitContext, cancelWait: cancelWait}
}

// 读按实际字节计费；超时保留未获额度的数据，允许重设 deadline 后继续读取。
func (connection *limitedConn) Read(buffer []byte) (int, error) {
	connection.readMutex.Lock()
	defer connection.readMutex.Unlock()
	if len(buffer) == 0 {
		return 0, nil
	}
	if len(buffer) > 64<<10 {
		buffer = buffer[:64<<10]
	}
	fromPending := len(connection.readPending) > 0
	var count int
	var err error
	if fromPending {
		count = copy(buffer, connection.readPending)
		if count == len(connection.readPending) {
			err = connection.readError
		}
	} else {
		count, err = connection.Conn.Read(buffer)
	}
	remaining := count
	for remaining > 0 {
		allowed, waitErr := connection.waitAllowance(remaining, false)
		if waitErr != nil {
			paid := count - remaining
			if fromPending {
				connection.readPending = connection.readPending[paid:]
			} else {
				connection.readPending = append([]byte(nil), buffer[paid:count]...)
				connection.readError = err
			}
			return paid, waitErr
		}
		remaining -= allowed
	}
	if fromPending {
		connection.readPending = connection.readPending[count:]
		if len(connection.readPending) == 0 {
			connection.readPending, connection.readError = nil, nil
		}
	}
	return count, err
}

// 大包必须逐段计费和发送，不能把预约截成 burst 后放行整个缓冲区。
func (connection *limitedConn) Write(buffer []byte) (int, error) {
	written := 0
	for written < len(buffer) {
		allowed, err := connection.waitAllowance(len(buffer)-written, true)
		if err != nil {
			return written, err
		}
		count, err := connection.Conn.Write(buffer[written : written+allowed])
		written += count
		if err != nil {
			return written, err
		}
		if count != allowed {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (connection *limitedConn) Close() error {
	connection.once.Do(func() {
		connection.cancel()
		if connection.onClose != nil {
			connection.onClose()
		}
	})
	return connection.Conn.Close()
}

func (connection *limitedConn) reserve(count int) error {
	for count > 0 {
		allowed, err := connection.waitAllowance(count, true)
		if err != nil {
			return err
		}
		count -= allowed
	}
	return nil
}

// 配置和 deadline 变更取消旧预约并重新计算；关闭连接则取消所有等待。
func (connection *limitedConn) resetWaitLocked() {
	connection.cancelWait()
	connection.waitContext, connection.cancelWait = context.WithCancel(connection.ctx)
}

func (connection *limitedConn) setRate(limit rate.Limit, burst int) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.resetWaitLocked()
	now := time.Now()
	connection.limiter.SetLimitAt(now, limit)
	connection.limiter.SetBurstAt(now, burst)
}

func (connection *limitedConn) waitAllowance(maximum int, write bool) (int, error) {
	for {
		connection.mu.Lock()
		if err := connection.ctx.Err(); err != nil {
			connection.mu.Unlock()
			return 0, err
		}
		generation := connection.waitContext
		deadline := connection.readDeadline
		if write {
			deadline = connection.writeDeadline
		}
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) {
			connection.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		count := min(maximum, 64<<10)
		if connection.limiter.Limit() != rate.Inf {
			count = min(count, connection.limiter.Burst())
		}
		reservation := connection.limiter.ReserveN(now, count)
		connection.mu.Unlock()
		if count <= 0 || !reservation.OK() {
			return 0, errors.New("invalid connection bandwidth configuration")
		}
		wait := time.NewTimer(reservation.DelayFrom(now))
		var deadlineTimer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			deadlineTimer = time.NewTimer(time.Until(deadline))
			timeout = deadlineTimer.C
		}
		var err error
		select {
		case <-wait.C:
		case <-generation.Done():
			err = context.Canceled
		case <-timeout:
			err = os.ErrDeadlineExceeded
		}
		wait.Stop()
		if deadlineTimer != nil {
			deadlineTimer.Stop()
		}
		connection.mu.Lock()
		changed := generation != connection.waitContext
		closed := connection.ctx.Err()
		connection.mu.Unlock()
		if err != nil || changed || closed != nil {
			reservation.CancelAt(time.Now())
		}
		if closed != nil {
			return 0, closed
		}
		if changed {
			continue
		}
		return count, err
	}
}

func (connection *limitedConn) SetDeadline(deadline time.Time) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if err := connection.Conn.SetDeadline(deadline); err != nil {
		return err
	}
	connection.readDeadline, connection.writeDeadline = deadline, deadline
	connection.resetWaitLocked()
	return nil
}

func (connection *limitedConn) SetReadDeadline(deadline time.Time) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if err := connection.Conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	connection.readDeadline = deadline
	connection.resetWaitLocked()
	return nil
}

func (connection *limitedConn) SetWriteDeadline(deadline time.Time) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if err := connection.Conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	connection.writeDeadline = deadline
	connection.resetWaitLocked()
	return nil
}
