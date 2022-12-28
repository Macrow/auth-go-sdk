package auth

type LocalAccessCode struct {
	Enable         bool
	Header         string
	EncryptContent bool
}

type LocalRandomKey struct {
	Enable bool
	Header string
}

type LocalUser struct {
	Header       string
	HeaderSchema string
}

type LocalClient struct {
	EnableIdAndSecret bool
	Header            string
	HeaderSchema      string
	EncryptContent    bool
}

type LocalAuditing struct {
	MetaBy string
}

type LocalAuthCheckerConfig struct {
	LocalAccessCode
	LocalRandomKey
	LocalUser
	LocalClient
	LocalAuditing
}
