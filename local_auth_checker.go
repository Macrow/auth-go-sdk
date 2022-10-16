package auth

type LocalAuthChecker struct {
	Config *LocalAuthCheckerConfig
}

func (c *LocalAuthChecker) ExtractAccessCode(f GetHeaderFun) (string, error) {
	return ExtractAccessCode(f, c.Config.LocalAccessCode.Header)
}

func (c *LocalAuthChecker) ExtractRandomKey(f GetHeaderFun) (string, error) {
	return ExtractRandomKey(f, c.Config.LocalAccessCode.Header)
}

func (c *LocalAuthChecker) ExtractUserToken(f GetHeaderFun) (string, error) {
	return ExtractUserToken(f, c.Config.LocalUser.Header, c.Config.LocalUser.HeaderSchema)
}

func (c *LocalAuthChecker) ExtractClientInfoAndToken(f GetHeaderFun) (string, string, string, error) {
	return ExtractClientInfoAndToken(f, c.Config.LocalClient.Header, c.Config.LocalClient.HeaderSchema)
}
