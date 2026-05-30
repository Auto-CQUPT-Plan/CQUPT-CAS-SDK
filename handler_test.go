package CQUPT_CAS_SDK

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Auto-CQUPT-Plan/CQUPT-CAS-SDK/client"
)

func TestLoginReturnsErrCaptchaRequiredWhenNoSolver(t *testing.T) {
	srv := newMockIDSServer(t, &mockIDSConfig{needCaptcha: true})
	defer srv.Close()
	withMockCoreFactory(t, srv.URL)

	sdk := GetSDK("2024user", "password")
	_, err := sdk.Login("http://example.com/service")
	if !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("Login error = %v, want ErrCaptchaRequired", err)
	}
}

func TestLoginUsesCaptchaSolverAndSubmitsCaptcha(t *testing.T) {
	cfg := &mockIDSConfig{needCaptcha: true}
	srv := newMockIDSServer(t, cfg)
	defer srv.Close()
	withMockCoreFactory(t, srv.URL)

	var solverImage []byte
	sdk := GetSDK("2024user", "password").WithCaptchaSolver(func(image []byte) (string, error) {
		solverImage = append([]byte(nil), image...)
		return "Ab12", nil
	})

	loc, err := sdk.Login("http://example.com/service")
	if err != nil {
		t.Fatal(err)
	}
	if loc != "http://example.com/service?ticket=ST-TEST" {
		t.Fatalf("location = %q", loc)
	}
	if string(solverImage) != string(mockCaptchaImage) {
		t.Fatalf("solver image = %v, want %v", solverImage, mockCaptchaImage)
	}

	form := cfg.lastLoginForm
	if form.Get("username") != "2024user" {
		t.Fatalf("submitted username = %q", form.Get("username"))
	}
	if form.Get("captcha") != "Ab12" {
		t.Fatalf("submitted captcha = %q", form.Get("captcha"))
	}
	if form.Get("execution") != "exec-1" {
		t.Fatalf("submitted execution = %q", form.Get("execution"))
	}
	if form.Get("password") == "" || form.Get("password") == "password" {
		t.Fatalf("password was not encrypted, submitted = %q", form.Get("password"))
	}
}

func TestLoginWithoutCaptchaStillSubmitsEmptyCaptcha(t *testing.T) {
	cfg := &mockIDSConfig{needCaptcha: false}
	srv := newMockIDSServer(t, cfg)
	defer srv.Close()
	withMockCoreFactory(t, srv.URL)

	sdk := GetSDK("2024user", "password")
	loc, err := sdk.Login("http://example.com/service")
	if err != nil {
		t.Fatal(err)
	}
	if loc != "http://example.com/service?ticket=ST-TEST" {
		t.Fatalf("location = %q", loc)
	}
	if cfg.lastLoginForm.Get("captcha") != "" {
		t.Fatalf("captcha = %q, want empty", cfg.lastLoginForm.Get("captcha"))
	}
}

func withMockCoreFactory(t *testing.T, serverURL string) {
	t.Helper()
	old := newHttpSpyderCore
	newHttpSpyderCore = func(service string) (*client.HttpSpyderCore, error) {
		return client.GetHttpSpyderCoreWithBaseURL(service, serverURL+"/authserver/login")
	}
	t.Cleanup(func() { newHttpSpyderCore = old })
}

var mockCaptchaImage = []byte{0xff, 0xd8, 'c', 'a', 'p', 0xff, 0xd9}

type mockIDSConfig struct {
	needCaptcha   bool
	lastLoginForm url.Values
}

func newMockIDSServer(t *testing.T, cfg *mockIDSConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authserver/login":
			if r.Method == http.MethodGet {
				w.Header().Add("Set-Cookie", "JSESSIONID=test-session; Path=/")
				_, _ = w.Write([]byte(`
					<html><body>
					<form id="pwdFromId" method="post" action="/authserver/login">
					<input id="pwdEncryptSalt" value="abcdefghijklmnop">
					<input id="execution" name="execution" value="exec-1">
					</form>
					</body></html>`))
				return
			}
			if r.Method == http.MethodPost {
				body, _ := io.ReadAll(r.Body)
				values, err := url.ParseQuery(string(body))
				if err != nil {
					t.Fatalf("parse posted form: %v; raw=%q", err, string(body))
				}
				cfg.lastLoginForm = values
				w.Header().Set("Location", "http://example.com/service?ticket=ST-TEST")
				w.WriteHeader(http.StatusFound)
				return
			}
		case "/authserver/checkNeedCaptcha.htl":
			if r.URL.Query().Get("username") != "2024user" {
				t.Fatalf("captcha username = %q", r.URL.Query().Get("username"))
			}
			if cfg.needCaptcha {
				_, _ = w.Write([]byte(`{"isNeed":true}`))
			} else {
				_, _ = w.Write([]byte(`{"isNeed":false}`))
			}
			return
		case "/authserver/getCaptcha.htl":
			if !cfg.needCaptcha {
				t.Fatal("getCaptcha called although captcha is not needed")
			}
			_, _ = w.Write(mockCaptchaImage)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
	}))
}
