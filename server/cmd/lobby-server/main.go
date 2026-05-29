// Lobby server -- between login and battle.
//
// Goley flow:
//
//	Entry server validates credentials → returns lobby endpoint
//	Client connects to lobby → RequestNextLogon(credential)
//	Lobby publishes game rooms, chat, friend list
//	Client creates/joins room → server returns battle endpoint + new credential
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/uintptr/goley-server/cmd/types"
	"github.com/uintptr/goley-server/internal/proudnet"
)

const defaultAddr = "0.0.0.0:2271"

type Lobies struct {
	lobbies map[string]*types.Lobby
}

var (
	lobbyMap = Lobies{make(map[string]*types.Lobby)}
)

func main() {

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(log)

	addr := defaultAddr
	if v := os.Getenv("LOBBY_ADDR"); v != "" {
		addr = v
	}

	srv := proudnet.NewServer(addr, log.With("svc", "lobby"))
	registerHandlers(srv, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("lobby server starting", "addr", addr)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

func registerHandlers(s *proudnet.Server, log *slog.Logger) {
	// LobbyC2S.RequestNextLogon -- credential from entry server
	s.Handle(proudnet.LobbyC2S_RequestNextLogon, func(c *proudnet.Conn, body *proudnet.Message) error {
		credential, err := body.ReadBytes(16)
		if err != nil {
			return err
		}
		log.Info("lobby logon", "hostID", c.HostID, "cred_len", len(credential))

		// Accept; reply with NotifyNextLogonSuccess + a HeroPublishInfo blob.
		// CHeroPublishInfo is a custom struct -- placeholder for now.
		resp := proudnet.NewMessage()
		resp.WriteBytes(make([]byte, 16)) // GamerGuid
		resp.WriteString("Goley")         // hero name (stand-in for full CHeroPublishInfo)
		return c.Send(proudnet.LobbyS2C_NotifyNextLogonSuccess, resp)
	})

	// LobbyC2S.Chat -- broadcast chat to everyone in lobby
	s.Handle(proudnet.LobbyC2S_Chat, func(c *proudnet.Conn, body *proudnet.Message) error {
		text, err := body.ReadString()
		if err != nil {
			return err
		}
		log.Info("lobby chat", "from", c.HostID, "text", text)
		// Broadcast as ShowChat([Guid heroGuid, String chatText])
		s.Broadcast(proudnet.LobbyS2C_ShowChat, func() *proudnet.Message {
			m := proudnet.NewMessage()
			m.WriteBytes(make([]byte, 16)) // sender heroGuid placeholder
			m.WriteString(text)
			return m
		})
		return nil
	})

	// LobbyC2S.RequestCreateGameRoom -- create a new room
	s.Handle(proudnet.LobbyC2S_RequestCreateGameRoom, func(c *proudnet.Conn, body *proudnet.Message) error {
		log.Info("create room request", "hostID", c.HostID)
		// CGameRoomParameter is custom -- placeholder
		lobbyName, err := body.ReadString()
		if err != nil {
			log.Error("Lobby name error!")
		}
		lobbyMap.lobbies[lobbyName] = &types.Lobby{LobbyID: int32(len(lobbyMap.lobbies)), LobbyName: lobbyName, IsGameFull: false, IsMatchStarted: false, Players: make(map[proudnet.HostID]*proudnet.Conn)}
		var lobbyResponse = func() *proudnet.Message {
			resp := proudnet.NewMessage()
			resp.WriteString(lobbyName)
			resp.WriteString(string(c.HostID))
			resp.WriteInt32(2272)
			return resp
		}
		// Broadcast to all players we have a new game room
		s.Broadcast(proudnet.LobbyS2C_GameRoom_Appear, lobbyResponse)
		return c.Send(proudnet.LobbyS2C_NotifyCreateRoomSuccess, lobbyResponse())
	})

	// EntryC2S.RequestLobbyList -- return one lobby pointing at 127.0.0.1:2271
	s.Handle(proudnet.EntryC2S_RequestLobbyList, func(c *proudnet.Conn, body *proudnet.Message) error {
		c.Send(proudnet.EntryS2C_LobbyList_Begin, proudnet.NewMessage())
		// LobbyList_Add([in] CStringW lobbyName, [in] NamedAddrPort serverAddr, [in] int gamerCount)
		// TODO test multiple lobbies
		for _, lobby := range lobbyMap.lobbies {
			res := proudnet.NewMessage()
			res.WriteString(lobby.LobbyName)
			res.WriteInt32(lobby.LobbyID)
			res.WriteInt32(lobby.GamerCount)
			c.Send(proudnet.EntryS2C_LobbyList_Add, res)
		}
		return c.Send(proudnet.EntryS2C_LobbyList_End, proudnet.NewMessage())
	})

	s.Handle(proudnet.LobbyC2S_RequestJoinGameRoom, func(c *proudnet.Conn, body *proudnet.Message) error {
		log.Info("join room request", "hostID", c.HostID)
		// CGameRoomParameter is custom -- placeholder
		lobbyName, err := body.ReadString()
		if err != nil {
			log.Error("Join request error")
		}
		// TODO store game room owner so they cannot join their room again.
		if lobby, ok := lobbyMap.lobbies[lobbyName]; ok {
			if lobby.GamerCount < 2 && !lobby.IsMatchStarted {
				var room = func() *proudnet.Message {
					resp := proudnet.NewMessage()
					resp.WriteString(lobby.LobbyName)
					resp.WriteInt32(lobby.LobbyID)
					return resp
				}
				c.Send(proudnet.LobbyS2C_NotifyJoinRoomSuccess, room())
				lobby.GamerCount += 1
				lobby.Players[c.HostID] = c
				if lobby.GamerCount == 2 {
					s.Broadcast(proudnet.LobbyS2C_GameRoom_Disappear, room)
					go handleStartGame(lobby)
				}
				return nil
			}
		}
		res := proudnet.NewMessage()
		c.Send(proudnet.LobbyS2C_NotifyJoinRoomFailed, res)
		return nil
	})
}

func handleStartGame(lobby *types.Lobby) {
	for _, player := range lobby.Players {
		resp := proudnet.NewMessage()
		resp.WriteString("127.0.0.1")
		resp.WriteInt32(2272)
		// Placeholders
		resp.WriteInt32(lobby.LobbyID)
		resp.WriteString("credentials_")
		player.Send(proudnet.LobbyS2C_GotoGameRoom, resp)
	}
}
