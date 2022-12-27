package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type aesEcb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *aesEcb {
	return &aesEcb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypt aesEcb

func newECBEncrypt(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypt)(newECB(b))
}

func (x *ecbEncrypt) BlockSize() int { return x.blockSize }

func (x *ecbEncrypt) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypt aesEcb

func newECBDecrypt(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypt)(newECB(b))
}

func (x *ecbDecrypt) BlockSize() int {
	return x.blockSize
}

func (x *ecbDecrypt) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func AesEcbEncrypt(plainText, secretKey []byte) (cipherText []byte, err error) {
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return nil, ErrAESKeyFail
	}
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	paddingText := PKCS5Padding(plainText, block.BlockSize())

	encrypted := make([]byte, len(paddingText))
	ecbEncrypt := newECBEncrypt(block)
	ecbEncrypt.CryptBlocks(encrypted, paddingText)

	return encrypted, nil
}

func AesEcbDecrypt(plainText, secretKey []byte) (cipherText []byte, err error) {
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return nil, ErrAESKeyFail
	}
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	ecbDecrypt := newECBDecrypt(block)
	decrypted := make([]byte, len(plainText))
	ecbDecrypt.CryptBlocks(decrypted, plainText)

	return PKCS5UnPadding(decrypted, ecbDecrypt.BlockSize())
}

func AesEcbEncryptBase64(plainText, key []byte) (cipherTextBase64 string, err error) {
	encryptBytes, err := AesEcbEncrypt(plainText, key)
	return base64.StdEncoding.EncodeToString(encryptBytes), err
}

func AesEcbDecryptByBase64(cipherTextBase64 string, key []byte) (plainText []byte, err error) {
	plainTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return []byte{}, err
	}
	return AesEcbDecrypt(plainTextBytes, key)
}

func PKCS5Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	newText := append(plainText, padText...)
	return newText
}

func PKCS5UnPadding(plainText []byte, blockSize int) ([]byte, error) {
	length := len(plainText)
	number := int(plainText[length-1])
	if number >= length || number > blockSize {
		return nil, ErrDecryptFail
	}
	return plainText[:length-number], nil
}
