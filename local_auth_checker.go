package auth

import "github.com/go-logr/logr"

type LocalAuthChecker struct {
	Config  *LocalAuthCheckerConfig
	AesUtil *AesUtil
	logger  logr.Logger
}

func (c *LocalAuthChecker) ExtractAccessCode(f GetHeaderFun) (string, error) {
	return ExtractAccessCode(f, c.Config.LocalAccessCode.Header, c.Config.LocalAccessCode.EncryptContent, aesUtil, c.logger)
}

func (c *LocalAuthChecker) ExtractRandomKey(f GetHeaderFun) (string, error) {
	return ExtractRandomKey(f, c.Config.LocalRandomKey.Header, c.Config.LocalRandomKey.EncryptContent, aesUtil, c.logger)
}

func (c *LocalAuthChecker) ExtractUserToken(f GetHeaderFun) (string, error) {
	return ExtractUserToken(f, c.Config.LocalUser.Header, c.Config.LocalUser.HeaderSchema)
}

func (c *LocalAuthChecker) ExtractClientInfoAndToken(f GetHeaderFun) (string, string, string, error) {
	return ExtractClientInfoAndToken(f, c.Config.LocalClient.Header, c.Config.LocalClient.HeaderSchema, c.Config.LocalClient.EncryptContent, aesUtil, c.logger)
}
