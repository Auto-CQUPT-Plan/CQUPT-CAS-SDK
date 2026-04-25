package client

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Auto-CQUPT-Plan/CQUPT-CAS-SDK/extractor"
)

func (r *HttpSpyderCore) initHttpCore(targetService string) error {
	// 生成Service的UrlEncode
	r.targetService = url.QueryEscape(targetService)

	// 创建全局请求头
	r.headers = map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
	}

	// 创建HttpClient
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 全局化
	r.client = client
	return nil
}

func (r *HttpSpyderCore) GenLoginForm(username, encPassword, execution string) *strings.Reader {
	s := fmt.Sprintf(
		"username=%s&password=%s&captcha=&_eventId=submit&cllt=userNameLogin&dllt=generalLogin&lt=&execution=%s",
		username,
		encPassword,
		execution,
	)

	return strings.NewReader(s)
}

func (r *HttpSpyderCore) GetGlobalCookie() error {
	finalURL := fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return err
	}

	for key, val := range r.headers {
		req.Header.Set(key, val)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}

	var cookies []string
	for _, cookieHeader := range resp.Header["Set-Cookie"] {
		if idx := strings.Index(cookieHeader, ";"); idx != -1 {
			cookieHeader = cookieHeader[:idx]
		}
		// 去除可能的空格
		cookieHeader = strings.TrimSpace(cookieHeader)
		if cookieHeader != "" {
			cookies = append(cookies, cookieHeader)
		}
	}

	r.cookies = strings.Join(cookies, "; ")
	r.headers["Cookie"] = r.cookies

	_ = resp.Body.Close()

	return nil
}

func (r *HttpSpyderCore) GetBasicData() (*BasicData, error) {
	data := &BasicData{}

	finalURL := fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return nil, err
	}

	for key, val := range r.headers {
		req.Header.Set(key, val)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	data.Execution = extractor.ExtractInputValue(bodyBytes, `id="execution"`, `name="execution"`)
	data.PwdEncryptSalt = extractor.ExtractInputValue(bodyBytes, `id="pwdEncryptSalt"`)

	_ = resp.Body.Close()

	return data, nil
}

func (r *HttpSpyderCore) GetLocation(body *strings.Reader) (string, error) {
	finalURL := fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)

	req, err := http.NewRequest("POST", finalURL, body)
	if err != nil {
		return "", err
	}

	for key, val := range r.headers {
		req.Header.Set(key, val)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}

	_ = resp.Body.Close()

	for key, val := range resp.Header {
		if key == "Location" {
			return val[0], nil
		}
	}

	return "", nil
}
