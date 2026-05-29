// Minimal ProudNet-compatible TCP server skeleton.
//
// Listens on a TCP port and processes incoming framed messages, dispatching
// RMI calls to registered handlers. Designed as the foundation for the
// Entry / Lobby / Battle game servers.
//
// LIMITATIONS (will be addressed as real protocol bytes are confirmed):
//   - No encryption (ProudNet uses AES-128 with per-session key from handshake)
//   - No reliable-UDP support yet
//   - No P2P relay yet
//   - Framing format is a scaffold; needs verification against live captures
//   - No keep-alive / ping handling
package proudnet

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
)

// RMIHandler is called when a known RMI ID arrives. It receives the connection
// state, parsed payload, and may reply via Conn.Send.
type RMIHandler func(c *Conn, body *Message) error

// Server is a single-port ProudNet-compatible listener.
type Server struct {
	addr     string
	handlers map[int32]RMIHandler

	nextHostID atomic.Int32
	mu         sync.RWMutex
	conns      map[HostID]*Conn

	log *slog.Logger
}

// Conn represents a single connected client (server-side state).
type Conn struct {
	HostID HostID
	conn   net.Conn
	srv    *Server
	log    *slog.Logger

	// User-attached state -- Account, character, lobby room, etc.
	State any
}

// NewServer creates a server bound to the given address. Call Register* to
// install handlers before calling ListenAndServe.
func NewServer(addr string, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		addr:     addr,
		handlers: make(map[int32]RMIHandler),
		conns:    make(map[HostID]*Conn),
		log:      log.With("addr", addr),
	}
	// Server is HostID 1; clients get 2, 3, ...
	s.nextHostID.Store(2)
	return s
}

// Handle registers a handler for the given RMI ID.
func (s *Server) Handle(rmiID int32, h RMIHandler) {
	s.handlers[rmiID] = h
}

// ListenAndServe starts accepting connections until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	s.log.Info("ProudNet server listening")

	for {
		nc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("accept", "err", err)
			continue
		}
		hostID := HostID(s.nextHostID.Add(1) - 1)
		c := &Conn{
			HostID: hostID,
			conn:   nc,
			srv:    s,
			log:    s.log.With("hostID", hostID, "remote", nc.RemoteAddr()),
		}
		s.mu.Lock()
		s.conns[hostID] = c
		s.mu.Unlock()
		go c.serve(ctx)
	}
}

func (c *Conn) serve(ctx context.Context) {
	defer func() {
		c.conn.Close()
		c.srv.mu.Lock()
		delete(c.srv.conns, c.HostID)
		c.srv.mu.Unlock()
		c.log.Info("connection closed")
	}()

	c.log.Info("connection accepted")

	// TODO: handshake exchange. ProudNet client expects a server-hello message
	// with protocol version and connection parameters; without that the client
	// will disconnect. We will need to capture a real handshake from the Goley
	// client and replay it here.

	for {
		if ctx.Err() != nil {
			return
		}
		f, err := ReadFrame(c.conn)
		if err != nil {
			if err != io.EOF {
				c.log.Error("read", "err", err)
			}
			return
		}

		c.log.Debug("frame", "type", fmt.Sprintf("0x%02x", f.MsgType), "body_len", len(f.Body))

		if f.MsgType == MessageTypeRMI {
			body := FromBytes(f.Body)
			// Skip the dest HostID -- server is destination, we already know.
			if _, err := body.ReadHostID(); err != nil {
				c.log.Warn("bad rmi header (dest)", "err", err)
				continue
			}
			rmiID, err := body.ReadInt32()
			if err != nil {
				c.log.Warn("bad rmi header (id)", "err", err)
				continue
			}
			name := RmiName(int(rmiID))
			if name == "" {
				name = fmt.Sprintf("RMI(%d)", rmiID)
			}
			c.log.Info("rmi recv", "id", rmiID, "name", name)

			if h, ok := c.srv.handlers[rmiID]; ok {
				if err := h(c, body); err != nil {
					c.log.Error("handler", "rmi", rmiID, "err", err)
				}
			} else {
				c.log.Warn("no handler", "rmi", rmiID, "name", name)
			}
		}
	}
}

// Send replies to this client with an RMI call (S2C direction).
func (c *Conn) Send(rmiID int32, args *Message) error {
	return WriteRMI(c.conn, c.HostID, rmiID, args)
}

// Broadcast sends to all currently connected clients.
func (s *Server) Broadcast(rmiID int32, build func() *Message) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.conns {
		if err := c.Send(rmiID, build()); err != nil {
			c.log.Warn("broadcast", "err", err)
		}
	}
}
