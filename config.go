package auth

type BasicConfig struct {
	AuthServiceBaseUrl string
	CurrentServiceName string
	CacheSplitter      string
}

type AccessCodeConfig struct {
	Enable         bool
	SkipTokenCheck bool
	Header         string
}

type RandomKeyConfig struct {
	Enable bool
	Header string
}

type JwtConfig struct {
	Issuer          string
	ExpireInMinutes int
	PublicKey       string
	PrivateKey      string
}

type UserConfig struct {
	Header       string
	HeaderSchema string
}

type ClientConfig struct {
	Id                string
	Secret            string
	EnableIdAndSecret bool
	AccessCode        string
	Header            string
	HeaderSchema      string
}

type AuditingConfig struct {
	MetaBy string
}

type HttpClientConfig struct {
	BasicConfig
	AccessCode AccessCodeConfig
	RandomKey  RandomKeyConfig
	Jwt        JwtConfig
	User       UserConfig
	Client     ClientConfig
	Auditing   AuditingConfig
}
