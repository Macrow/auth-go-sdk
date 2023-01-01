package auth

type Service struct {
	AuthServiceBaseUrl string
	CurrentServiceName string
	EncryptKey         string
	EnableTraceLog     bool
}

type AccessCode struct {
	Enable             bool
	SkipUserTokenCheck bool
	Header             string
	EncryptContent     bool
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
	EncryptContent    bool
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
