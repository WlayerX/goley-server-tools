// Package proudnet implements minimal ProudNet protocol for Goley server emulator.
//
// Goley uses ProudNet by Nettention (Korean), with 3-server architecture identical to
// the ProudNet sample "CasualGame2":
//
//   EntryServer  (login, character select)      -- RMI base 1500/2000
//   LobbyServer  (lobby, game room list)        -- RMI base 3000/4000
//   BattleServer (match server)                 -- RMI base 5000/6000
//   P2P C2C      (in-match peer-to-peer)        -- RMI base 7000
//
// PIDL syntax (declaration):
//
//   global EntryC2S 1500 {
//       RequestFirstLogon([in] String gamerID, [in] String gamerPassword);  // ID = 1501
//       ...
//   }
//
// RMI ID = base + sequence (1-indexed).
package proudnet

// HostID -- ProudNet host identifier
type HostID int32

const (
	HostIDNone   HostID = 0
	HostIDServer HostID = 1 // Server is always HostID 1; clients start at 2.
)

// MessagePriority levels (from ProudNet Enums.h)
type MessagePriority int

const (
	MessagePriorityRing0  MessagePriority = 0 // ProudNet internal (ping)
	MessagePriorityRing1  MessagePriority = 1 // ProudNet internal
	MessagePriorityHigh   MessagePriority = 2
	MessagePriorityMedium MessagePriority = 3 // Most common
	MessagePriorityLow    MessagePriority = 4
	MessagePriorityRing99 MessagePriority = 5 // Hole-punch, lowest
)

// MessageReliability -- TCP vs UDP
type MessageReliability int

const (
	MessageReliabilityUnreliable MessageReliability = 0 // UDP
	MessageReliabilityReliable   MessageReliability = 1 // TCP / reliable UDP
)

// EncryptMode -- per-message encryption flag
type EncryptMode int

const (
	EncryptModeNone   EncryptMode = 0
	EncryptModeSecure EncryptMode = 1 // AES, established at handshake
)

// =============================================================================
// Goley RMI ID base values (educated guess -- verify against binary RMI symbols).
// These mirror the CasualGame2 sample bases. Goley specific values to be confirmed
// from a captured handshake / disassembled RTTI / actual packet trace.
// =============================================================================

const (
	// Entry server (login, account, character select)
	EntryC2SBase = 1500
	EntryS2CBase = 2000

	// Lobby server (lobby chat, game room create/join)
	LobbyC2SBase = 3000
	LobbyS2CBase = 4000

	// Battle server (in-game)
	BattleC2SBase = 5000
	BattleS2CBase = 6000

	// Peer-to-peer (during match)
	BattleC2CBase = 7000
)

// EntryC2S RMI IDs (educated guess from CasualGame2 sample).
// TODO: verify against Goley binary.
const (
	EntryC2S_RequestReturnToEntry  = EntryC2SBase + 1
	EntryC2S_RequestCreateNewGamer = EntryC2SBase + 2
	EntryC2S_RequestFirstLogon     = EntryC2SBase + 3
	EntryC2S_RequestHeroSlots      = EntryC2SBase + 4
	EntryC2S_RequestSelectHero     = EntryC2SBase + 5
	EntryC2S_RequestAddHero        = EntryC2SBase + 6
	EntryC2S_RequestRemoveHero     = EntryC2SBase + 7
	EntryC2S_RequestLobbyList      = EntryC2SBase + 8

	// Goley-specific (extracted from BinaryTr unpacked memory)
	EntryC2S_RequestLogin         = EntryC2SBase + 10
	EntryC2S_RequestBigCardInfo   = EntryC2SBase + 11
)

const (
	EntryS2C_NotifyCreateNewGamerSuccess = EntryS2CBase + 1
	EntryS2C_NotifyCreateNewGamerFailed  = EntryS2CBase + 2
	EntryS2C_NotifyUnauthedAccess        = EntryS2CBase + 3
	EntryS2C_ShowError                   = EntryS2CBase + 4
	EntryS2C_NotifyFirstLogonFailed      = EntryS2CBase + 5
	EntryS2C_NotifyReturnToEntryFailed   = EntryS2CBase + 6
	EntryS2C_NotifyFirstLogonSuccess     = EntryS2CBase + 7
	EntryS2C_NotifySelectHeroFailed      = EntryS2CBase + 8
	EntryS2C_NotifySelectHeroSuccess     = EntryS2CBase + 9
	EntryS2C_HeroList_Begin              = EntryS2CBase + 10
	EntryS2C_HeroList_Add                = EntryS2CBase + 11
	EntryS2C_HeroList_End                = EntryS2CBase + 12
	EntryS2C_RemovedHeroList_Begin       = EntryS2CBase + 13
	EntryS2C_RemovedHeroList_Add         = EntryS2CBase + 14
	EntryS2C_RemovedHeroList_End         = EntryS2CBase + 15
	EntryS2C_NotifySelectedHero          = EntryS2CBase + 16
	EntryS2C_NotifyAddHeroSuccess        = EntryS2CBase + 17
	EntryS2C_NotifyAddHeroFailed         = EntryS2CBase + 18
	EntryS2C_NotifyRemoveHeroSuccess     = EntryS2CBase + 19
	EntryS2C_LobbyList_Begin             = EntryS2CBase + 20
	EntryS2C_LobbyList_Add               = EntryS2CBase + 21
	EntryS2C_LobbyList_End               = EntryS2CBase + 22

	// Goley-specific (extracted from BinaryTr unpacked memory)
	EntryS2C_NotifyLoginOk     = EntryS2CBase + 30
	EntryS2C_NotifyLoginFailed = EntryS2CBase + 31
	EntryS2C_GotoLobby         = EntryS2CBase + 32
)

const (
	LobbyC2S_RequestNextLogon       = LobbyC2SBase + 1
	LobbyC2S_NotifyChannelFormReady = LobbyC2SBase + 2
	LobbyC2S_Chat                   = LobbyC2SBase + 3
	LobbyC2S_RequestCreateGameRoom  = LobbyC2SBase + 4
	LobbyC2S_RequestJoinGameRoom    = LobbyC2SBase + 5
)

const (
	LobbyS2C_NotifyUnauthedAccess    = LobbyS2CBase + 1
	LobbyS2C_ShowError               = LobbyS2CBase + 2
	LobbyS2C_NotifyNextLogonFailed   = LobbyS2CBase + 3
	LobbyS2C_NotifyNextLogonSuccess  = LobbyS2CBase + 4
	LobbyS2C_HeroSlot_Appear         = LobbyS2CBase + 5
	LobbyS2C_HeroSlot_Disappear      = LobbyS2CBase + 6
	LobbyS2C_GameRoom_Appear         = LobbyS2CBase + 7
	LobbyS2C_GameRoom_ShowState      = LobbyS2CBase + 8
	LobbyS2C_GameRoom_Disappear      = LobbyS2CBase + 9
	LobbyS2C_LocalHeroSlot_Appear    = LobbyS2CBase + 10
	LobbyS2C_ShowChat                = LobbyS2CBase + 11
	LobbyS2C_NotifyCreateRoomFailed  = LobbyS2CBase + 12
	LobbyS2C_NotifyCreateRoomSuccess = LobbyS2CBase + 13
	LobbyS2C_NotifyJoinRoomFailed    = LobbyS2CBase + 14
	LobbyS2C_NotifyJoinRoomSuccess   = LobbyS2CBase + 15

	// Goley-specific (extracted from BinaryTr unpacked memory)
	LobbyS2C_GotoGameRoom = LobbyS2CBase + 20
)

// RmiName returns a human-readable name for known RMI IDs (or "" if unknown).
func RmiName(id int) string {
	switch id {
	// Entry C2S
	case EntryC2S_RequestFirstLogon:
		return "EntryC2S.RequestFirstLogon"
	case EntryC2S_RequestLogin:
		return "EntryC2S.RequestLogin"
	case EntryC2S_RequestBigCardInfo:
		return "EntryC2S.RequestBigCardInfo"
	case EntryC2S_RequestLobbyList:
		return "EntryC2S.RequestLobbyList"
	case EntryC2S_RequestSelectHero:
		return "EntryC2S.RequestSelectHero"
	// Entry S2C
	case EntryS2C_NotifyFirstLogonSuccess:
		return "EntryS2C.NotifyFirstLogonSuccess"
	case EntryS2C_NotifyFirstLogonFailed:
		return "EntryS2C.NotifyFirstLogonFailed"
	case EntryS2C_NotifyLoginOk:
		return "EntryS2C.NotifyLoginOk"
	case EntryS2C_NotifyLoginFailed:
		return "EntryS2C.NotifyLoginFailed"
	case EntryS2C_GotoLobby:
		return "EntryS2C.GotoLobby"
	case EntryS2C_LobbyList_Begin:
		return "EntryS2C.LobbyList_Begin"
	case EntryS2C_LobbyList_Add:
		return "EntryS2C.LobbyList_Add"
	case EntryS2C_LobbyList_End:
		return "EntryS2C.LobbyList_End"
	// Lobby C2S
	case LobbyC2S_RequestNextLogon:
		return "LobbyC2S.RequestNextLogon"
	case LobbyC2S_Chat:
		return "LobbyC2S.Chat"
	case LobbyC2S_RequestCreateGameRoom:
		return "LobbyC2S.RequestCreateGameRoom"
	// Lobby S2C
	case LobbyS2C_NotifyNextLogonSuccess:
		return "LobbyS2C.NotifyNextLogonSuccess"
	case LobbyS2C_ShowChat:
		return "LobbyS2C.ShowChat"
	case LobbyS2C_GotoGameRoom:
		return "LobbyS2C.GotoGameRoom"
	}
	return ""
}
