package auth

type JwtUtilConfig struct {
	RedisConfig
	JwtConfig
}

type RedisConfig struct {
	Address  string
	Db       int
	Password string
}

type JwtConfig struct {
	Prefix          string
	CacheSplitter   string
	Issuer          string
	ExpireInMinutes int
	PublicKey       []byte
	PrivateKey      []byte
}
