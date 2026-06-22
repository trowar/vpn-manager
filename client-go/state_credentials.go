package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
)

func saveLoginCredentials(webURL, username, password string, rememberPassword bool) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	encrypted := ""
	if rememberPassword {
		encrypted, err = encryptLocalSecret(password)
		if err != nil {
			return err
		}
	}
	state.SavedLogin = SavedLogin{
		WebURL:            strings.TrimRight(strings.TrimSpace(webURL), "/"),
		Username:          strings.TrimSpace(username),
		EncryptedPassword: encrypted,
		RememberPassword:  rememberPassword,
	}
	return saveState(state)
}

func loadSavedLogin() SavedLogin {
	state, err := loadState()
	if err != nil {
		return SavedLogin{}
	}
	return state.SavedLogin
}

func decryptSavedPassword(saved SavedLogin) string {
	if !saved.RememberPassword {
		return ""
	}
	password, err := decryptLocalSecret(saved.EncryptedPassword)
	if err != nil {
		return ""
	}
	return password
}

func localSecretKey() [32]byte {
	hostname, _ := os.Hostname()
	home, _ := os.UserHomeDir()
	seed := strings.Join([]string{appName, hostname, home}, "\n")
	return sha256.Sum256([]byte(seed))
}

func encryptLocalSecret(secret string) (string, error) {
	key := localSecretKey()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	return base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func decryptLocalSecret(encrypted string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encrypted))
	if err != nil {
		return "", err
	}
	key := localSecretKey()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("本地密码密文无效")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
