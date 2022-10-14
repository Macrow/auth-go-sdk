package config

type Service struct {
	AuthServiceBaseUrl string
	CurrentServiceName string
}

type AccessCode struct {
	Enable             bool
	SkipUserTokenCheck bool
	Header             string
}

type RandomKey struct {
	Enable bool
	Header string
}

type User struct {
	Header       string
	HeaderSchema string
}

type Client struct {
	Id                string
	Secret            string
	EnableIdAndSecret bool
	AccessCode        string
	Header            string
	HeaderSchema      string
}

type Auditing struct {
	MetaBy string
}

type HttpClientConfig struct {
	Service
	AccessCode
	RandomKey
	User
	Client
	Auditing
}
