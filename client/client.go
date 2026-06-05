package client

import (
	"encoding/json"
	"errors"
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

func (r *HttpSpyderCore) GenLoginForm(username, encPassword, captcha, execution string) *strings.Reader {
	s := fmt.Sprintf(
		"username=%s&password=%s&captcha=%s&_eventId=submit&cllt=userNameLogin&dllt=generalLogin&lt=&execution=%s",
		url.QueryEscape(username),
		encPassword,
		url.QueryEscape(captcha),
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

	r.mergeCookiesFromResponse(resp)

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

	r.mergeCookiesFromResponse(resp)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	data.Execution = extractor.ExtractInputValue(bodyBytes, `id="execution"`, `name="execution"`)
	data.PwdEncryptSalt = extractor.ExtractInputValue(bodyBytes, `id="pwdEncryptSalt"`)
	data.FormAction = extractor.ExtractAnyFormAction(bodyBytes, "pwdFromId", "casLoginForm")

	// 记录表单 action 作为 POST URL，供 GetLocation 使用。
	// action 可能是绝对路径(/authserver/login)、空字符串、或完整 URL。
	if data.FormAction != "" {
		r.postURL = r.resolveLoginURL(data.FormAction)
	}

	_ = resp.Body.Close()

	return data, nil
}

// GetLocation 提交登录表单并返回服务端下发的 Location 重定向。
// 如果服务端下发“踢出会话”页面（HTTP 200 + 页面包含该提示），会自动取出新的 execution、
// 使用 _eventId=continue 二次提交，再返回最终 Location。
func (r *HttpSpyderCore) GetLocation(body *strings.Reader) (string, error) {
	finalURL := r.loginPostURL()

	req, err := http.NewRequest("POST", finalURL, body)
	if err != nil {
		return "", err
	}

	for key, val := range r.headers {
		req.Header.Set(key, val)
	}
	req.Header.Set("Referer", fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService))
	req.Header.Set("Origin", r.originOf(r.baseUrl))

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}

	r.mergeCookiesFromResponse(resp)

	// 重定向：正常登录成功路径。
	if loc := resp.Header.Get("Location"); loc != "" {
		_ = resp.Body.Close()
		return loc, nil
	}

	// 200 且页面提示踢出会话，需要二次确认。
	if resp.StatusCode == http.StatusOK {
		html, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return "", err
		}
		if strings.Contains(string(html), "\u8e22\u51fa\u4f1a\u8bdd") {
			return r.confirmKickoutAndGetLocation(html)
		}
		return "", nil
	}

	_ = resp.Body.Close()
	return "", nil
}

// confirmKickoutAndGetLocation 处理“踢出会话”二次确认页面。
// 页面中含一个新的 execution 隐藏域，需要 POST execution + _eventId=continue。
func (r *HttpSpyderCore) confirmKickoutAndGetLocation(html []byte) (string, error) {
	exec2 := extractor.ExtractInputValue(html, `name="execution"`)
	if exec2 == "" {
		return "", errors.New("kickout page: execution not found")
	}

	form := fmt.Sprintf("execution=%s&_eventId=continue", url.QueryEscape(exec2))
	req, err := http.NewRequest("POST", r.loginPostURL(), strings.NewReader(form))
	if err != nil {
		return "", err
	}
	for key, val := range r.headers {
		req.Header.Set(key, val)
	}
	req.Header.Set("Referer", fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService))
	req.Header.Set("Origin", r.originOf(r.baseUrl))

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	r.mergeCookiesFromResponse(resp)

	if loc := resp.Header.Get("Location"); loc != "" {
		return loc, nil
	}
	return "", errors.New("kickout confirm: no Location header")
}

// mergeCookiesFromResponse 合并响应中的 Set-Cookie 到内部 cookie 缓存。
// 同名 cookie 后到达的值会覆盖先前的值，避免登录过程中累加旧值导致服务端 401。
func (r *HttpSpyderCore) mergeCookiesFromResponse(resp *http.Response) {
	if resp == nil {
		return
	}

	// 解析当前已有 cookie 到 map
	jar := map[string]string{}
	order := []string{}
	if r.cookies != "" {
		for _, part := range strings.Split(r.cookies, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if idx := strings.Index(part, "="); idx > 0 {
				name := part[:idx]
				if _, ok := jar[name]; !ok {
					order = append(order, name)
				}
				jar[name] = part[idx+1:]
			}
		}
	}

	// 合并新 Set-Cookie
	for _, sc := range resp.Header["Set-Cookie"] {
		if idx := strings.Index(sc, ";"); idx != -1 {
			sc = sc[:idx]
		}
		sc = strings.TrimSpace(sc)
		if sc == "" {
			continue
		}
		if idx := strings.Index(sc, "="); idx > 0 {
			name := sc[:idx]
			if _, ok := jar[name]; !ok {
				order = append(order, name)
			}
			jar[name] = sc[idx+1:]
		}
	}

	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, name+"="+jar[name])
	}
	r.cookies = strings.Join(parts, "; ")
	r.headers["Cookie"] = r.cookies
}

// checkNeedCaptchaResp 是 /authserver/checkNeedCaptcha.htl 的响应结构。
type checkNeedCaptchaResp struct {
	IsNeed bool `json:"isNeed"`
}

// CheckNeedCaptcha 查询当前账号本次登录是否需要图形验证码。
// IDS 接口: GET https://ids.cqupt.edu.cn/authserver/checkNeedCaptcha.htl?username=<username>
func (r *HttpSpyderCore) CheckNeedCaptcha(username string) (bool, error) {
	base := strings.TrimSuffix(r.baseUrl, "/login")
	finalURL := fmt.Sprintf("%s/checkNeedCaptcha.htl?username=%s&_=%d",
		base,
		url.QueryEscape(username),
		time.Now().UnixMilli(),
	)

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return false, err
	}
	for key, val := range r.headers {
		req.Header.Set(key, val)
	}
	req.Header.Set("Referer", fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService))

	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	r.mergeCookiesFromResponse(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	trim := strings.TrimSpace(string(body))
	if trim == "" {
		return false, nil
	}
	// 接口正常返回 JSON: {"isNeed": true/false}
	if strings.HasPrefix(trim, "{") {
		var data checkNeedCaptchaResp
		if err := json.Unmarshal([]byte(trim), &data); err != nil {
			return false, fmt.Errorf("parse checkNeedCaptcha resp: %w (raw=%q)", err, trim)
		}
		return data.IsNeed, nil
	}
	// 兼容旧实现：纯文本 true/false
	switch strings.ToLower(trim) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("unexpected checkNeedCaptcha resp: %q", trim)
}

// GetCaptcha 拉取一张图形验证码图片字节流，通常是 JPEG。
// IDS 接口: GET https://ids.cqupt.edu.cn/authserver/getCaptcha.htl?<timestamp>
// 调用前应当先 CheckNeedCaptcha 确认需要验证码，并复用同一个 HttpSpyderCore 以共享 cookie。
func (r *HttpSpyderCore) GetCaptcha() ([]byte, error) {
	base := strings.TrimSuffix(r.baseUrl, "/login")
	finalURL := fmt.Sprintf("%s/getCaptcha.htl?%d", base, time.Now().UnixMilli())

	req, err := http.NewRequest("GET", finalURL, nil)
	if err != nil {
		return nil, err
	}
	for key, val := range r.headers {
		req.Header.Set(key, val)
	}
	req.Header.Set("Referer", fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService))

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	r.mergeCookiesFromResponse(resp)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getCaptcha: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errors.New("getCaptcha: empty body")
	}
	return body, nil
}

// loginPostURL 返回登录 POST 的目标 URL。优先使用从页面提取的 form action，
// 退回使用 baseUrl?service=...。
func (r *HttpSpyderCore) loginPostURL() string {
	if r.postURL != "" {
		return r.postURL
	}
	return fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)
}

// resolveLoginURL 把页面中拿到的 form action 解析成完整 URL。
// action 可能是：
//   - 完整 URL: https://ids.cqupt.edu.cn/authserver/login?...
//   - 绝对路径: /authserver/login
//   - 相对路径: login 或 ?execution=...
//
// 统一补上 service query 参数。
func (r *HttpSpyderCore) resolveLoginURL(action string) string {
	base, err := url.Parse(r.baseUrl)
	if err != nil {
		return fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)
	}
	ref, err := url.Parse(action)
	if err != nil {
		return fmt.Sprintf("%s?service=%s", r.baseUrl, r.targetService)
	}
	resolved := base.ResolveReference(ref)

	// 保留/补充 service：IDS 的 action 上一般不带 service，需要手动补。
	q := resolved.Query()
	if q.Get("service") == "" && r.targetService != "" {
		// targetService 已是经 url.QueryEscape 的原始字符串，这里需要原始值才能被 Encode 正确处理。
		// 直接在 RawQuery 拼接避免二次编码。
		if resolved.RawQuery == "" {
			resolved.RawQuery = "service=" + r.targetService
		} else {
			resolved.RawQuery += "&service=" + r.targetService
		}
	}
	return resolved.String()
}

// originOf 返回一个 URL 的 scheme://host 部分，用于 Origin 请求头。
func (r *HttpSpyderCore) originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
