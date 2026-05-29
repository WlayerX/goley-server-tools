// login-server is a packet logger for the Goley TCP login/game protocol.
//
// Listens on 2270 (login/auth) and 20260 (game/lobby).
// For each incoming connection:
//   - logs source address
//   - reads up to 64 KB
//   - hex-dumps the bytes (to discover packet structure)
//   - tries a few generic responses to see what the client does next
//
// Until the protocol is reverse-engineered, the goal is to capture as many
// real client packets as possible so we can pattern-match the wire format.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/uintptr/goley-server/internal/common"
)

func main() {
	loginPort := flag.Int("login-port", 2270, "login/auth server port (per RE)")
	gamePort := flag.Int("game-port", 20260, "game/world server port (per RE)")
	host := flag.String("host", "0.0.0.0", "bind host")
	flag.Parse()

	log := common.NewLogger("login-server")
	defer log.Close()
	log.Logf("=== Goley login/game packet logger ===")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); listen(*host, *loginPort, "LOGIN", log) }()
	go func() { defer wg.Done(); listen(*host, *gamePort, "GAME", log) }()
	wg.Wait()
}

func listen(host string, port int, label string, log *common.Logger) {
	addr := fmt.Sprintf("%s:%d", host, port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Logf("[%s] FATAL bind %s: %v", label, addr, err)
		os.Exit(1)
	}
	log.Logf("[%s] listening on %s", label, addr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Logf("[%s] accept err: %v", label, err)
			continue
		}
		go handle(conn, label, log)
	}
}

func handle(conn net.Conn, label string, log *common.Logger) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Logf("[%s] CONNECT from %s", label, remote)

	// Read with timeout to capture initial burst
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	var buf [65536]byte
	totalRead := 0
	for {
		n, err := conn.Read(buf[totalRead:])
		if n > 0 {
			totalRead += n
		}
		if err == io.EOF {
			log.Logf("[%s] %s EOF after %d bytes", label, remote, totalRead)
			break
		}
		if err != nil {
			// timeout or other error
			if strings.Contains(err.Error(), "timeout") {
				log.Logf("[%s] %s read timeout after %d bytes", label, remote, totalRead)
				break
			}
			log.Logf("[%s] %s read err: %v (after %d bytes)", label, remote, err, totalRead)
			break
		}
		if totalRead == len(buf) {
			break
		}
		// extend deadline if we keep receiving
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	}

	if totalRead == 0 {
		log.Logf("[%s] %s no data, closing", label, remote)
		return
	}

	data := buf[:totalRead]
	log.Logf("[%s] %s captured %d bytes:\n%s", label, remote, totalRead, common.HexDump(data, 1024))

	// Save to pcap-like log file for offline analysis
	saveCapture(label, remote, data, log)

	// Try a generic response and see what the client does
	// (most binary protocols start with [length][opcode][...] or [magic][...])
	// For now we just close -- packet logger only.
}

// saveCapture writes each captured packet to a separate file under logs/captures/
func saveCapture(label, remote string, data []byte, log *common.Logger) {
	dir := "logs/captures"
	_ = os.MkdirAll(dir, 0755)
	ts := time.Now().Format("20060102_150405.000")
	safeRemote := strings.ReplaceAll(remote, ":", "_")
	name := fmt.Sprintf("%s/%s_%s_%s.bin", dir, ts, label, safeRemote)
	if err := os.WriteFile(name, data, 0644); err != nil {
		log.Logf("[%s] saveCapture err: %v", label, err)
		return
	}
	log.Logf("[%s] saved capture: %s (%d bytes)", label, name, len(data))
}
