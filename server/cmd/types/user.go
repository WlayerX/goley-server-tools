package types

type UserRole int

const (
	Player UserRole = 0
	Mod    UserRole = 1
	Admin  UserRole = 2
)

// TODO: implement other variables
type User struct {
	playername string
	// user       UserRole
	//exp        float32
	//level int32
	//gold  int32
	//gp    int32
	//jp    int32
}
