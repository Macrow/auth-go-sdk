package auth

import (
	"crypto/cipher"
	"encoding/base64"
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
	a.encryptBlock.CryptBlocks(encrypted, plainText)

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
	a.decryptBlock.CryptBlocks(decrypted, plainText)

	encryptBytes, err := PKCS5UnPadding(decrypted, a.block.BlockSize())
	if err != nil {
		return "", err
	}
	return (string)(encryptBytes), err
}
