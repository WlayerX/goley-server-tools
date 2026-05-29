package types

import "github.com/uintptr/goley-server/internal/proudnet"

type Lobby struct {
	LobbyID        int32
	LobbyName      string
	GamerCount     int32
	IsGameFull     bool
	IsMatchStarted bool
	// Convert to player
	Players map[proudnet.HostID]*proudnet.Conn
}
