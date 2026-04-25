package CQUPT_CAS_SDK

type SDK struct {
	UserName string
	Password string
}

func GetSDK(username string, password string) *SDK {
	return &SDK{UserName: username, Password: password}
}
