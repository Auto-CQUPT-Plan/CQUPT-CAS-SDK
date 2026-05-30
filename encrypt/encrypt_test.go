package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// 与 EncryptPasssword 中 key 长度处理保持一致：salt 不足 16 字节用 \x00 补齐，超过则截断到 16。
func normalizeKey(salt string) []byte {
	key := []byte(strings.TrimSpace(salt))
	if len(key) < 16 {
		key = append(key, make([]byte, 16-len(key))...)
	} else if len(key) > 16 {
		key = key[:16]
	}
	return key
}

func TestEncryptPasssword_ProducesValidCiphertext(t *testing.T) {
	salt := "abcdefghijklmnop" // 正好 16 字节
	password := "test_pwd_123"

	got, err := EncryptPasssword(password, salt)
	if err != nil {
		t.Fatalf("EncryptPasssword err: %v", err)
	}
	if got == "" {
		t.Fatal("got empty ciphertext")
	}

	// 应当是 URL-encoded 的 base64。先 unescape 再 base64 decode。
	rawB64, err := url.QueryUnescape(got)
	if err != nil {
		t.Fatalf("QueryUnescape: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		t.Fatalf("base64 decode: %v (raw=%q)", err, rawB64)
	}
	if len(raw)%aes.BlockSize != 0 {
		t.Fatalf("ciphertext len %d not multiple of %d", len(raw), aes.BlockSize)
	}
	// 密文长度 = pad(64 字节随机前缀 + len(password))
	// 64 + 12 = 76 → pad 到 80
	if want := 80; len(raw) != want {
		t.Errorf("ciphertext len = %d, want %d", len(raw), want)
	}
}

func TestEncryptPasssword_Randomness(t *testing.T) {
	// 同样的明文+salt，多次加密结果应不同（随机前缀 + 随机 IV）
	salt := "abcdefghijklmnop"
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		got, err := EncryptPasssword("p", salt)
		if err != nil {
			t.Fatalf("EncryptPasssword: %v", err)
		}
		if seen[got] {
			t.Fatalf("duplicate ciphertext on attempt %d: %s", i, got)
		}
		seen[got] = true
	}
}

func TestEncryptPasssword_ShortSalt(t *testing.T) {
	// 短 salt 应当被零填充到 16 字节，且加密成功
	got, err := EncryptPasssword("pwd", "short")
	if err != nil {
		t.Fatalf("EncryptPasssword: %v", err)
	}
	rawB64, _ := url.QueryUnescape(got)
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if len(raw)%aes.BlockSize != 0 {
		t.Errorf("ciphertext len %d not multiple of %d", len(raw), aes.BlockSize)
	}
}

func TestEncryptPasssword_LongSalt(t *testing.T) {
	// 超长 salt 应当被截断到 16 字节
	got, err := EncryptPasssword("pwd", "this_is_a_very_long_salt_string_xxxx")
	if err != nil {
		t.Fatalf("EncryptPasssword: %v", err)
	}
	if got == "" {
		t.Fatal("empty ciphertext")
	}
}

func TestEncryptPasssword_EmptyPassword(t *testing.T) {
	// 空密码也应该可加密（明文为 64 字节随机前缀）
	got, err := EncryptPasssword("", "abcdefghijklmnop")
	if err != nil {
		t.Fatalf("EncryptPasssword: %v", err)
	}
	rawB64, _ := url.QueryUnescape(got)
	raw, _ := base64.StdEncoding.DecodeString(rawB64)
	// 64 字节随机前缀 + 0 字节密码 → pad 到 80 字节
	if want := 80; len(raw) != want {
		t.Errorf("ciphertext len = %d, want %d", len(raw), want)
	}
}

func TestEncryptPasssword_DecryptableWithKnownIV(t *testing.T) {
	// 校验加密格式正确：用同样的 key、PKCS7 模式可以解出 "随机前缀(64) + 密码"
	// 这里通过私有函数验证而不是端到端 decrypt（因为 IV 是随机的，无法外部得知）。
	salt := "abcdefghijklmnop"
	password := "mypassword"

	key := normalizeKey(salt)
	iv := []byte("0123456789abcdef")
	prefix := strings.Repeat("X", 64)
	plain := prefix + password

	encrypted, err := aesEncryptGo([]byte(plain), key, iv)
	if err != nil {
		t.Fatalf("aesEncryptGo: %v", err)
	}

	// 解密
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	// 去 PKCS7 padding
	pad := int(decrypted[len(decrypted)-1])
	if pad < 1 || pad > aes.BlockSize {
		t.Fatalf("invalid pad %d", pad)
	}
	plainBack := string(decrypted[:len(decrypted)-pad])
	if plainBack != plain {
		t.Errorf("decrypted = %q, want %q", plainBack, plain)
	}
}

func TestPkcs7Padding(t *testing.T) {
	cases := []struct {
		in       []byte
		block    int
		wantLen  int
		wantLast byte
	}{
		{[]byte("a"), 16, 16, 15},
		{[]byte(strings.Repeat("a", 15)), 16, 16, 1},
		{[]byte(strings.Repeat("a", 16)), 16, 32, 16}, // 满块也要补一整块
		{[]byte(""), 16, 16, 16},
	}
	for _, c := range cases {
		got := pkcs7Padding(c.in, c.block)
		if len(got) != c.wantLen {
			t.Errorf("len = %d, want %d (in_len=%d)", len(got), c.wantLen, len(c.in))
		}
		if got[len(got)-1] != c.wantLast {
			t.Errorf("last byte = %d, want %d", got[len(got)-1], c.wantLast)
		}
	}
}

func TestAesEncryptGo_InvalidIV(t *testing.T) {
	key := []byte("0123456789abcdef")
	_, err := aesEncryptGo([]byte("hello"), key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for short IV")
	}
}

func TestAesEncryptGo_InvalidKey(t *testing.T) {
	_, err := aesEncryptGo([]byte("hello"), []byte("not16bytes"), []byte("0123456789abcdef"))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestRandomStringGo_LengthAndCharset(t *testing.T) {
	for _, n := range []int{0, 1, 16, 64, 100} {
		s, err := randomStringGo(n)
		if err != nil {
			t.Fatalf("len=%d err: %v", n, err)
		}
		if len(s) != n {
			t.Errorf("len(%q) = %d, want %d", s, len(s), n)
		}
		for _, c := range s {
			if !strings.ContainsRune(aesChars, c) {
				t.Errorf("char %q not in charset", c)
			}
		}
	}
}

func TestRandomStringGo_Randomness(t *testing.T) {
	a, _ := randomStringGo(32)
	b, _ := randomStringGo(32)
	if a == b {
		t.Errorf("two random strings collide: %q", a)
	}
}
