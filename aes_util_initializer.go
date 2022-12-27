package auth

import (
	"crypto/aes"
	"errors"
)

var (
	aesUtil *AesUtil
)

func NewAesUtil(key string) *AesUtil {
	if len(key) == 0 {
		return nil
	}
	if aesUtil != nil {
		return aesUtil
	}
	if len(key) != 16 {
		panic(errors.New("AES加密key长度必须是16位"))
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	aesUtil = &AesUtil{
		block:        block,
		encryptBlock: newECBEncrypt(block),
		decryptBlock: newECBDecrypt(block),
	}
	return aesUtil
}
