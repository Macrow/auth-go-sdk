package auth

type RawJwtUser struct {
	Id   string  `json:"id"`   // 用户id
	Name string  `json:"name"` // 用户登录名
	Kind string  `json:"kind"` // 用户类型
	Did  string  `json:"did"`  // 设备id
	Iss  string  `json:"iss"`  // 签发者
	Iat  float64 `json:"iat"`  // 签发时间
	Exp  float64 `json:"exp"`  // 过期时间
}

type JwtUser struct {
	RawJwtUser
	Token string `json:"token"` // 令牌字符串
}
