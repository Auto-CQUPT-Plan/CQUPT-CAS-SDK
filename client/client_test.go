package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestCore(t *testing.T, serverURL string) *HttpSpyderCore {
	t.Helper()
	hc := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &HttpSpyderCore{
		client:        hc,
		baseUrl:       serverURL + "/authserver/login",
		targetService: "http%3A%2F%2Fexample.com%2Fservice%3Fx%3D1",
		headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent":   "test-agent",
		},
	}
}

func TestGenLoginFormEscapesUsernameAndCaptcha(t *testing.T) {
	core := &HttpSpyderCore{}
	body, err := io.ReadAll(core.GenLoginForm("2024+测试", "enc+pwd%3D", "a b+中", "exec-1"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	assertContains(t, got, "username=2024%2B%E6%B5%8B%E8%AF%95")
	assertContains(t, got, "password=enc+pwd%3D")
	assertContains(t, got, "captcha=a+b%2B%E4%B8%AD")
	assertContains(t, got, "execution=exec-1")
}

func TestMergeCookiesFromResponseOverridesDuplicateName(t *testing.T) {
	core := &HttpSpyderCore{
		cookies: "JSESSIONID=old; route=r1",
		headers: map[string]string{},
	}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Add("Set-Cookie", "JSESSIONID=new; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", "CASTGC=tgc; Path=/")

	core.mergeCookiesFromResponse(resp)

	want := "JSESSIONID=new; route=r1; CASTGC=tgc"
	if core.cookies != want {
		t.Fatalf("cookies = %q, want %q", core.cookies, want)
	}
	if core.headers["Cookie"] != want {
		t.Fatalf("Cookie header = %q, want %q", core.headers["Cookie"], want)
	}
}

func TestGetBasicDataExtractsFormActionAndSetsPostURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authserver/login" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Add("Set-Cookie", "JSESSIONID=abc; Path=/")
		_, _ = w.Write([]byte(`
			<html><body>
			<form id="pwdFromId" method="post" action="/authserver/login">
			<input id="pwdEncryptSalt" value="salt-123">
			<input id="execution" name="execution" value="exec-123">
			</form>
			</body></html>`))
	}))
	defer srv.Close()

	core := newTestCore(t, srv.URL)
	data, err := core.GetBasicData()
	if err != nil {
		t.Fatal(err)
	}

	if data.PwdEncryptSalt != "salt-123" {
		t.Fatalf("salt = %q", data.PwdEncryptSalt)
	}
	if data.Execution != "exec-123" {
		t.Fatalf("execution = %q", data.Execution)
	}
	if data.FormAction != "/authserver/login" {
		t.Fatalf("form action = %q", data.FormAction)
	}
	assertContains(t, core.postURL, srv.URL+"/authserver/login")
	assertContains(t, core.postURL, "service=http%3A%2F%2Fexample.com%2Fservice%3Fx%3D1")
	if core.headers["Cookie"] != "JSESSIONID=abc" {
		t.Fatalf("Cookie header = %q", core.headers["Cookie"])
	}
}

func TestResolveLoginURL(t *testing.T) {
	core := &HttpSpyderCore{
		baseUrl:       "https://ids.cqupt.edu.cn/authserver/login",
		targetService: "http%3A%2F%2Fexample.com%2Fcallback",
	}

	cases := []struct {
		name   string
		action string
		want   string
	}{
		{
			name:   "absolute path",
			action: "/authserver/login",
			want:   "https://ids.cqupt.edu.cn/authserver/login?service=http%3A%2F%2Fexample.com%2Fcallback",
		},
		{
			name:   "relative path",
			action: "login",
			want:   "https://ids.cqupt.edu.cn/authserver/login?service=http%3A%2F%2Fexample.com%2Fcallback",
		},
		{
			name:   "full url keeps existing query",
			action: "https://ids.cqupt.edu.cn/authserver/login?foo=bar",
			want:   "https://ids.cqupt.edu.cn/authserver/login?foo=bar&service=http%3A%2F%2Fexample.com%2Fcallback",
		},
		{
			name:   "service already present",
			action: "https://ids.cqupt.edu.cn/authserver/login?service=x",
			want:   "https://ids.cqupt.edu.cn/authserver/login?service=x",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := core.resolveLoginURL(c.action); got != c.want {
				t.Fatalf("resolveLoginURL(%q) = %q, want %q", c.action, got, c.want)
			}
		})
	}
}

func TestCheckNeedCaptchaJSONAndCookieMerge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authserver/checkNeedCaptcha.htl" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("username") != "2024测试" {
			t.Fatalf("username query = %q", r.URL.Query().Get("username"))
		}
		w.Header().Add("Set-Cookie", "captchaToken=tok; Path=/")
		_, _ = w.Write([]byte(`{"isNeed":true}`))
	}))
	defer srv.Close()

	core := newTestCore(t, srv.URL)
	need, err := core.CheckNeedCaptcha("2024测试")
	if err != nil {
		t.Fatal(err)
	}
	if !need {
		t.Fatal("need captcha = false, want true")
	}
	if core.headers["Cookie"] != "captchaToken=tok" {
		t.Fatalf("Cookie header = %q", core.headers["Cookie"])
	}
}

func TestCheckNeedCaptchaTextFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("false"))
	}))
	defer srv.Close()

	core := newTestCore(t, srv.URL)
	need, err := core.CheckNeedCaptcha("user")
	if err != nil {
		t.Fatal(err)
	}
	if need {
		t.Fatal("need captcha = true, want false")
	}
}

func TestGetCaptchaReturnsBytesAndMergesCookie(t *testing.T) {
	image := []byte{0xff, 0xd8, 0xff, 0xd9}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authserver/getCaptcha.htl" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Add("Set-Cookie", "captchaSession=abc; Path=/")
		_, _ = w.Write(image)
	}))
	defer srv.Close()

	core := newTestCore(t, srv.URL)
	got, err := core.GetCaptcha()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(image) {
		t.Fatalf("captcha bytes = %v, want %v", got, image)
	}
	if core.headers["Cookie"] != "captchaSession=abc" {
		t.Fatalf("Cookie header = %q", core.headers["Cookie"])
	}
}

func TestGetLocationNormalRedirectUsesResolvedPostURL(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/login" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Location", "http://example.com/callback?ticket=ST-1")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	core := newTestCore(t, srv.URL)
	core.postURL = srv.URL + "/custom/login?service=" + core.targetService
	loc, err := core.GetLocation(strings.NewReader("username=u&password=p"))
	if err != nil {
		t.Fatal(err)
	}
	if loc != "http://example.com/callback?ticket=ST-1" {
		t.Fatalf("location = %q", loc)
	}
	if gotBody != "username=u&password=p" {
		t.Fatalf("body = %q", gotBody)
	}
}

func TestGetLocationHandlesKickoutConfirmation(t *testing.T) {
	postCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authserver/login" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		postCount++
		body, _ := io.ReadAll(r.Body)
		switch postCount {
		case 1:
			assertContains(t, string(body), "username=u")
			_, _ = w.Write([]byte(`<html><body>踢出会话<input name="execution" value="exec-continue"></body></html>`))
		case 2:
			got := string(body)
			assertContains(t, got, "execution=exec-continue")
			assertContains(t, got, "_eventId=continue")
			w.Header().Set("Location", "http://example.com/callback?ticket=ST-2")
			w.WriteHeader(http.StatusFound)
		default:
			t.Fatalf("unexpected extra request #%d", postCount)
		}
	}))
	defer srv.Close()

	core := newTestCore(t, srv.URL)
	loc, err := core.GetLocation(strings.NewReader("username=u&password=p"))
	if err != nil {
		t.Fatal(err)
	}
	if loc != "http://example.com/callback?ticket=ST-2" {
		t.Fatalf("location = %q", loc)
	}
	if postCount != 2 {
		t.Fatalf("postCount = %d, want 2", postCount)
	}
}

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Fatalf("%q does not contain %q", s, substr)
	}
}
