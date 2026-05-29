// Battle server -- match-time server.
//
// In Goley's architecture this server:
//   1. Accepts the credential from the lobby (TCP)
//   2. Runs the UDP relay for P2P match traffic
//   3. Reports match results back to the data store
//
// Implementation is a thin wrapper around proudnet.Server + proudnet.UDPRelay.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/uintptr/goley-server/internal/proudnet"
)

const (
	defaultTCPAddr = "0.0.0.0:2272"
	defaultUDPAddr = "0.0.0.0:2273"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(log)

	tcpAddr := defaultTCPAddr
	if v := os.Getenv("BATTLE_TCP_ADDR"); v != "" {
		tcpAddr = v
	}
	udpAddr := defaultUDPAddr
	if v := os.Getenv("BATTLE_UDP_ADDR"); v != "" {
		udpAddr = v
	}

	srv := proudnet.NewServer(tcpAddr, log.With("svc", "battle-tcp"))
	relay := proudnet.NewUDPRelay(udpAddr, log.With("svc", "battle-udp"))

	registerHandlers(srv, relay, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		log.Info("battle TCP starting", "addr", tcpAddr)
		if err := srv.ListenAndServe(ctx); err != nil {
			log.Error("tcp listen", "err", err)
		}
	}()
	go func() {
		defer wg.Done()
		log.Info("battle UDP relay starting", "addr", udpAddr)
		if err := relay.ListenAndServe(ctx); err != nil {
			log.Error("udp listen", "err", err)
		}
	}()
	wg.Wait()
}

func registerHandlers(s *proudnet.Server, relay *proudnet.UDPRelay, log *slog.Logger) {
	// BattleC2S.RequestNextLogon -- client arrives from lobby with a credential
	s.Handle(proudnet.BattleC2SBase+1, func(c *proudnet.Conn, body *proudnet.Message) error {
		// Read room GUID + credential (16 bytes each -- placeholder)
		roomGuid, err := body.ReadBytes(16)
		if err != nil {
			return err
		}
		credential, err := body.ReadBytes(16)
		if err != nil {
			return err
		}
		log.Info("battle logon", "hostID", c.HostID, "room_len", len(roomGuid), "cred_len", len(credential))

		// Accept everything for now -- production would validate credential.
		// TODO: register peer with UDP relay once we know their UDP source.

		// Send NotifyNextLogonSuccess (placeholder)
		resp := proudnet.NewMessage()
		resp.WriteBytes(make([]byte, 16)) // GamerGuid placeholder
		return c.Send(proudnet.BattleS2CBase+4, resp)
	})

	// Other Battle RMI handlers (RequestToggleBattleReady, RequestStartPlayMode,
	// NotifyLoadFinished, LeaveBattleRoom, RequestLocalHeroSpawn, ...) TODO.
}
