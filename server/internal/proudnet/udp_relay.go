// UDP relay -- fallback path for P2P traffic when NAT hole-punching fails.
//
// ProudNet design: clients try to connect peer-to-peer directly (with UPnP
// + hole-punching). If that fails the server forwards UDP packets between
// peers. The relay does not parse the payload -- it just forwards UDP
// datagrams keyed by the destination HostID embedded in the ProudNet
// frame header.
//
// Default port 2271 (one above the entry server). Configurable via
// RELAY_ADDR.
package proudnet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

// PeerAddr is a UDP endpoint identified by HostID.
type PeerAddr struct {
	HostID HostID
	Addr   *net.UDPAddr
}

// UDPRelay forwards UDP datagrams between peers based on the destination
// HostID embedded in each packet's first 5 bytes (1-byte MsgType + int32 HostID).
type UDPRelay struct {
	addr string

	mu    sync.RWMutex
	peers map[HostID]*net.UDPAddr // HostID -> last seen UDP source

	log *slog.Logger
}

// NewUDPRelay creates a relay bound to addr.
func NewUDPRelay(addr string, log *slog.Logger) *UDPRelay {
	if log == nil {
		log = slog.Default()
	}
	return &UDPRelay{
		addr:  addr,
		peers: make(map[HostID]*net.UDPAddr),
		log:   log.With("addr", addr),
	}
}

// RegisterPeer associates a HostID with a known UDP endpoint. The Lobby/Entry
// server calls this when a client joins, so the relay knows where to forward
// peer traffic.
func (r *UDPRelay) RegisterPeer(id HostID, addr *net.UDPAddr) {
	r.mu.Lock()
	r.peers[id] = addr
	r.mu.Unlock()
	r.log.Info("peer registered", "hostID", id, "addr", addr)
}

// UnregisterPeer removes a HostID mapping.
func (r *UDPRelay) UnregisterPeer(id HostID) {
	r.mu.Lock()
	delete(r.peers, id)
	r.mu.Unlock()
}

// ListenAndServe runs the relay loop until ctx is cancelled.
func (r *UDPRelay) ListenAndServe(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", r.addr)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", r.addr, err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", r.addr, err)
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	r.log.Info("UDP relay listening")

	buf := make([]byte, 64*1024)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.log.Error("read", "err", err)
			continue
		}

		// Parse destination HostID from the leading bytes.
		dest, srcID, err := parsePeerHeader(buf[:n])
		if err != nil {
			r.log.Debug("bad packet", "from", src, "err", err)
			continue
		}

		// Update sender mapping based on the source HostID
		// (so we know where to deliver replies).
		if srcID != HostIDNone {
			r.RegisterPeer(srcID, src)
		}

		// Look up the destination.
		r.mu.RLock()
		destAddr, ok := r.peers[dest]
		r.mu.RUnlock()
		if !ok {
			r.log.Debug("no peer for dest", "dest", dest, "from", src)
			continue
		}

		// Forward as-is. The ProudNet client expects to see the original
		// frame format on the wire.
		if _, err := conn.WriteToUDP(buf[:n], destAddr); err != nil {
			r.log.Warn("forward", "err", err, "dest", dest)
		}
	}
}

// parsePeerHeader pulls the destination HostID and (best-effort) source
// HostID from a ProudNet peer frame. Layout (placeholder, to verify against
// real capture):
//
//   byte 0      : MessageType
//   byte 1..4   : Dest HostID (int32, LE)
//   byte 5..8   : Source HostID (int32, LE)  -- if present
func parsePeerHeader(b []byte) (dest, src HostID, err error) {
	if len(b) < 5 {
		return 0, 0, errors.New("packet too short")
	}
	dest = HostID(int32(binary.LittleEndian.Uint32(b[1:5])))
	if len(b) >= 9 {
		src = HostID(int32(binary.LittleEndian.Uint32(b[5:9])))
	}
	return
}
