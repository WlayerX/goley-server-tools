// Entry server -- login and character selection.
//
// Mirror of ProudNet CasualGame2 "EntryServer" sample, adapted for Goley.
// Listens on a TCP port; handles RequestFirstLogon, RequestHeroSlots, etc.
//
// Default port 2270 (matches original Joygame login server port hint).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/uintptr/goley-server/internal/proudnet"
)

const defaultAddr = "0.0.0.0:2270"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(log)

	addr := defaultAddr
	if v := os.Getenv("ENTRY_ADDR"); v != "" {
		addr = v
	}

	srv := proudnet.NewServer(addr, log.With("svc", "entry"))
	registerHandlers(srv, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("entry server starting", "addr", addr)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

func registerHandlers(s *proudnet.Server, log *slog.Logger) {
	// Goley-specific: RequestLogin (Goley uses this, not RequestFirstLogon)
	s.Handle(proudnet.EntryC2S_RequestLogin, func(c *proudnet.Conn, body *proudnet.Message) error {
		gamerID, err := body.ReadString()
		if err != nil {
			return err
		}
		password, _ := body.ReadString()
		log.Info("RequestLogin", "id", gamerID, "pw_len", len(password))

		// NotifyLoginOk (Goley) -- gamerGuid + credential
		resp := proudnet.NewMessage()
		resp.WriteBytes(makeFakeGuid(gamerID))
		resp.WriteBytes(makeFakeGuid("cred_" + gamerID))
		return c.Send(proudnet.EntryS2C_NotifyLoginOk, resp)
	})

	// EntryC2S.RequestFirstLogon (CasualGame2 sample style, kept as fallback)
	s.Handle(proudnet.EntryC2S_RequestFirstLogon, func(c *proudnet.Conn, body *proudnet.Message) error {
		gamerID, err := body.ReadString()
		if err != nil {
			return err
		}
		password, err := body.ReadString()
		if err != nil {
			return err
		}
		log.Info("login attempt", "id", gamerID, "pw_len", len(password))

		// Always succeed for now -- credential is a fake GUID
		resp := proudnet.NewMessage()
		// NotifyFirstLogonSuccess([in] Guid Gamerguid, [in] Guid credential)
		// Guid = 16 bytes; we use a simple deterministic stub for now.
		gamerGuid := makeFakeGuid(gamerID)
		credential := makeFakeGuid("credential_" + gamerID)
		resp.WriteBytes(gamerGuid)
		resp.WriteBytes(credential)

		// We sending our player to lobby server
		lobby := proudnet.NewMessage()
		lobby.WriteString("127.0.0.1")
		lobby.WriteInt32(2271)
		lobby.WriteBytes(gamerGuid)
		lobby.WriteBytes(credential)
		// Probably a success popup
		c.Send(proudnet.EntryS2C_NotifyFirstLogonSuccess, resp)
		return c.Send(proudnet.EntryS2C_GotoLobby, lobby)
	})

	// Wrong server???
	// EntryC2S.RequestHeroSlots -- return a dummy hero list
	s.Handle(proudnet.EntryC2S_RequestHeroSlots, func(c *proudnet.Conn, body *proudnet.Message) error {
		// HeroList_Begin
		c.Send(proudnet.EntryS2C_HeroList_Begin, proudnet.NewMessage())
		// HeroList_Add([in] CStringW heroName, [in] Guid heroGuid, [in] int heroType, [in] LONGLONG heroScore)
		add := proudnet.NewMessage()
		add.WriteString("Goley")
		add.WriteBytes(makeFakeGuid("hero_default"))
		add.WriteInt32(1)    // heroType
		add.WriteInt64(1000) // heroScore
		c.Send(proudnet.EntryS2C_HeroList_Add, add)
		// HeroList_End
		return c.Send(proudnet.EntryS2C_HeroList_End, proudnet.NewMessage())
	})
}

// makeFakeGuid returns a 16-byte deterministic GUID-shaped identifier built
// from a string seed. Sufficient for prototype login flow; production should
// use real GUIDs.
func makeFakeGuid(seed string) []byte {
	out := make([]byte, 16)
	for i, b := range []byte(seed) {
		out[i%16] ^= b
	}
	return out
}
