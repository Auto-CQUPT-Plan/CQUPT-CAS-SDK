package CQUPT_CAS_SDK

// CaptchaSolver 由调用方提供，负责把验证码图片（通常是 JPEG 字节流）
// 转换为最终提交给 IDS 的字符串。
//
// 典型实现：
//   - 人工输入：把图片落盘后在 TUI 提示用户输入
//   - 本地 OCR：用 gosseract / paddleocr-go 等识别
//   - 远程打码：调云端打码平台 HTTP API
//
// 返回空字符串视为放弃，登录会因验证码错误而失败。
type CaptchaSolver func(image []byte) (string, error)

type SDK struct {
	UserName string
	Password string

	// CaptchaSolver 可选；若为 nil 且 IDS 要求验证码，则 Login 会返回错误。
	CaptchaSolver CaptchaSolver
}

func GetSDK(username string, password string) *SDK {
	return &SDK{UserName: username, Password: password}
}

// WithCaptchaSolver 链式注册验证码解决方案，返回自身便于链式调用。
func (r *SDK) WithCaptchaSolver(solver CaptchaSolver) *SDK {
	r.CaptchaSolver = solver
	return r
}
