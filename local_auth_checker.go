package auth

import (
	"context"
	"net/http"
)

type LocalAuthChecker struct {
	Config *LocalAuthCheckerConfig
	Ctx    context.Context
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

func (c *LocalAuthChecker) GetSkipByAccessCode() bool {
	if c.Ctx == nil {
		return false
	}
	return c.Ctx.Value(KeySkipByAccessCode).(bool)
}

func (c *LocalAuthChecker) SetSkipByAccessCode(skip bool) {
	if c.Ctx != nil {
		c.Ctx = context.WithValue(c.Ctx, KeySkipByAccessCode, skip)
	}
}

func (c *LocalAuthChecker) GetJwtUser() *JwtUser {
	if c.Ctx == nil {
		return nil
	}
	return c.Ctx.Value(KeyJwtUser).(*JwtUser)
}

func (c *LocalAuthChecker) GetCustomAuth() interface{} {
	if c.Ctx == nil {
		return nil
	}
	return c.Ctx.Value(KeyCustomAuth)
}

func (c *LocalAuthChecker) GetCustomPerm() interface{} {
	if c.Ctx == nil {
		return nil
	}
	return c.Ctx.Value(KeyCustomPerm)
}

func (c *LocalAuthChecker) GetClientId() *string {
	if c.Ctx == nil {
		return nil
	}
	return c.Ctx.Value(KeyClientId).(*string)
}
