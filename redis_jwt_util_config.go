package auth

type Redis struct {
	Address  string
	Db       int
	Password string
}

type Jwt struct {
	Prefix          string
	CacheSplitter   string
	Issuer          string
	ExpireInMinutes int
	PublicKey       []byte
	PrivateKey      []byte
}

type JwtUtilConfig struct {
	Redis
	Jwt
}
