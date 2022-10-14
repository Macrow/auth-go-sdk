package auth

import (
	"net/http"
)

type LocalAuthChecker struct {
	Config *LocalAuthCheckerConfig
}

func (c *LocalAuthChecker) ExtractAccessCode(r *http.Request) string {
	return ExtractCommonHeader(r, c.Config.LocalAccessCode.Header)
}

func (c *LocalAuthChecker) ExtractRandomKey(r *http.Request) string {
	return ExtractCommonHeader(r, c.Config.LocalRandomKey.Header)
}

func (c *LocalAuthChecker) ExtractUserToken(r *http.Request) (string, error) {
	return ExtractUserToken(r, c.Config.LocalUser.Header, c.Config.LocalUser.HeaderSchema)
}

func (c *LocalAuthChecker) ExtractClientInfoAndToken(r *http.Request) (string, string, string, error) {
	return ExtractClientInfoAndToken(r, c.Config.LocalClient.Header, c.Config.LocalClient.HeaderSchema)
}
