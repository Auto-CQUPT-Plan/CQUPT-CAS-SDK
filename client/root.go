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

	// postURL 是登录表单实际 POST 的完整 URL，为空时退回 baseUrl?service=...。
	// 由 GetBasicData 根据页面 <form id="pwdFromId" action="..."> 填充。
	postURL string
}

type BasicData struct {
	PwdEncryptSalt string `json:"pwdEncryptSalt"`
	Execution      string `json:"execution"`
	FormAction     string `json:"formAction"`
}

func GetHttpSpyderCore(targetService string) (*HttpSpyderCore, error) {
	return GetHttpSpyderCoreWithBaseURL(targetService, "https://ids.cqupt.edu.cn/authserver/login")
}

// GetHttpSpyderCoreWithBaseURL 创建指定 IDS login base URL 的 HTTP 核心。
// 生产环境通常使用 GetHttpSpyderCore；该函数主要用于私有化 IDS、集成测试或本地 httptest。
func GetHttpSpyderCoreWithBaseURL(targetService, baseUrl string) (*HttpSpyderCore, error) {
	r := &HttpSpyderCore{baseUrl: baseUrl}
	if err := r.initHttpCore(targetService); err != nil {
		return nil, err
	}
	return r, nil
}
