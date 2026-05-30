package CQUPT_CAS_SDK

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Auto-CQUPT-Plan/CQUPT-CAS-SDK/client"
	"github.com/Auto-CQUPT-Plan/CQUPT-CAS-SDK/encrypt"
)

// ErrCaptchaRequired 表示 IDS 要求验证码，但 SDK 未注册 CaptchaSolver。
var ErrCaptchaRequired = errors.New("ids: captcha required but no CaptchaSolver registered")

var newHttpSpyderCore = client.GetHttpSpyderCore

func (r *SDK) Login(service string) (location string, err error) {
	// 初始化Http核心
	core, err := newHttpSpyderCore(service)
	if err != nil {
		return "", err
	}

	// 获取全局Cookie
	err = core.GetGlobalCookie()
	if err != nil {
		return "", err
	}

	// 获取基础数据
	data, err := core.GetBasicData()
	if err != nil {
		return "", err
	}

	// 用盐加密密码
	encPasswd, err := encrypt.EncryptPasssword(r.Password, data.PwdEncryptSalt)
	if err != nil {
		return "", err
	}

	// 处理图形验证码
	captcha, err := r.resolveCaptcha(core)
	if err != nil {
		return "", err
	}

	// 生成Login的POST表单数据
	body := core.GenLoginForm(r.UserName, encPasswd, captcha, data.Execution)

	// 执行登录流程
	loc, err := core.GetLocation(body)
	if err != nil {
		return "", err
	}

	return loc, nil
}

// resolveCaptcha 在 IDS 要求验证码时获取图片并调用 CaptchaSolver。
// 不需要验证码时返回空字符串。
func (r *SDK) resolveCaptcha(core *client.HttpSpyderCore) (string, error) {
	need, err := core.CheckNeedCaptcha(r.UserName)
	if err != nil {
		// 探测失败时按"不需要验证码"降级处理，避免接口波动导致整个登录失败
		return "", nil
	}
	if !need {
		return "", nil
	}

	if r.CaptchaSolver == nil {
		return "", ErrCaptchaRequired
	}

	img, err := core.GetCaptcha()
	if err != nil {
		return "", fmt.Errorf("fetch captcha: %w", err)
	}

	code, err := r.CaptchaSolver(img)
	if err != nil {
		return "", fmt.Errorf("solve captcha: %w", err)
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "", errors.New("captcha solver returned empty string")
	}
	return code, nil
}
