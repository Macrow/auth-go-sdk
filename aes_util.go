package auth

import (
	"crypto/cipher"
	"encoding/base64"
	"github.com/go-errors/errors"
)

// AesUtil AES加密采用128位AES/ECB/PKCS5Padding，不使用偏移量，最后用Base64输出
type AesUtil struct {
	block        cipher.Block
	encryptBlock cipher.BlockMode
	decryptBlock cipher.BlockMode
}

func (a *AesUtil) encrypt(content string) (string, error) {
	if content == "" {
		return "", ErrEmptyContent
	}
	plainText := ([]byte)(content)
	plainText = PKCS5Padding(plainText, a.block.BlockSize())
	encrypted := make([]byte, len(plainText))
	var errCatch error = nil
	a.CryptBlocks(a.encryptBlock, encrypted, plainText, errCatch)
	if errCatch != nil {
		return "", ErrEncryptFail
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (a *AesUtil) decrypt(content string) (string, error) {
	if content == "" {
		return "", ErrEmptyContent
	}
	plainText, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return "", err
	}
	decrypted := make([]byte, len(plainText))
	var errCatch error = nil
	a.CryptBlocks(a.encryptBlock, decrypted, plainText, errCatch)
	if errCatch != nil {
		return "", ErrDecryptFail
	}

	encryptBytes, err := PKCS5UnPadding(decrypted, a.block.BlockSize())
	if err != nil {
		return "", err
	}
	return (string)(encryptBytes), err
}

func (a *AesUtil) CryptBlocks(block cipher.BlockMode, dist, src []byte, errCatch error) {
	defer func() {
		if err := recover(); err != nil {
			errCatch = errors.New(err)
		}
	}()
	block.CryptBlocks(dist, src)
}
