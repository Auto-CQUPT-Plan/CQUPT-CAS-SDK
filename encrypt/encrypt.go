package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
)

var aesChars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

func randomStringGo(length int) (string, error) {
	result := make([]byte, length)
	charsLen := big.NewInt(int64(len(aesChars)))
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, charsLen)
		if err != nil {
			return "", err
		}
		result[i] = aesChars[num.Int64()]
	}
	return string(result), nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func aesEncryptGo(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != block.BlockSize() {
		return nil, errors.New("invalid iv size")
	}

	plaintext = pkcs7Padding(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

func EncryptPasssword(password, salt string) (string, error) {
	randomStr, err := randomStringGo(64)
	if err != nil {
		return "", fmt.Errorf("random error: %w", err)
	}

	passwordStr := randomStr + password

	key := []byte(strings.TrimSpace(salt))
	if len(key) < 16 {
		key = append(key, make([]byte, 16-len(key))...)
	} else if len(key) > 16 {
		key = key[:16]
	}

	iv, err := randomStringGo(16)
	if err != nil {
		return "", fmt.Errorf("gen IV fail: %w", err)
	}

	encrypted, err := aesEncryptGo([]byte(passwordStr), key, []byte(iv))
	if err != nil {
		return "", fmt.Errorf("AES encrypt fail: %w", err)
	}

	encryptedBase64 := base64.StdEncoding.EncodeToString(encrypted)

	encryptedURL := url.QueryEscape(encryptedBase64)

	return encryptedURL, nil
}
