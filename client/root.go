package client

import (
	"net/http"
)

type HttpSpyderCore struct {
	client        *http.Client
	cookies       string
	targetService string
	baseUrl       string
	headers       map[string]string
}

type BasicData struct {
	PwdEncryptSalt string `json:"pwdEncryptSalt"`
	Execution      string `json:"execution"`
}

func GetHttpSpyderCore(targetService string) (*HttpSpyderCore, error) {
	r := &HttpSpyderCore{baseUrl: "https://ids.cqupt.edu.cn/authserver/login"}
	if err := r.initHttpCore(targetService); err != nil {
		return nil, err
	}

	return r, nil
}
