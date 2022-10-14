package auth

const (
	DefaultCachePrefix       = "Jwt"
	DefaultCacheSplitter     = "::"
	DefaultIssuer            = "auth-go-sdk"
	DefaultHeaderRandomKey   = "Random-Key"
	DefaultHeaderAccessCode  = "Access-Code"
	DefaultHeaderUserToken   = "Authorization"
	DefaultHeaderClientToken = "HttpClient-Authorization"
	DefaultHeaderSchema      = "Bearer"
	DefaultMetaBy            = "id"

	JwtTokenClaimsId          = "id"
	JwtTokenClaimsName        = "name"
	JwtTokenClaimsKind        = "kind"
	JwtTokenClaimsDeviceId    = "did"
	JwtTokenClaimsIssuer      = "iss"
	JwtTokenClaimsIssueAt     = "iat"
	JwtTokenClaimsExpireAt    = "exp"
	ClientIdAndSecretSplitter = "@"
	DidAndIatJoiner           = "-"

	MsgServerFail            = "访问服务失败"
	MsgAuthServerFail        = "访问鉴权服务失败"
	MsgUserTokenEmpty        = "未提供用户令牌"
	MsgClientTokenEmpty      = "未提供客户端令牌"
	MsgClientIdOrSecretEmpty = "未提供客户端Id和秘钥"
	MsgUserTokenFail         = "用户令牌错误或失效"
	MsgClientTokenFail       = "客户端验证失败"
	MsgAuthFail              = "身份验证失败"
	MsgPermFail              = "权限验证失败"
	MsgInternalError         = "服务内部错误"
	MsgJwtErrFormat          = "令牌格式错误"
	MsgJwtErrVersion         = "令牌版本错误"

	UrlPostCheckAuth             = "/current/jwt"
	UrlPostCheckPermByCode       = "/current/check-operation"
	UrlPostCheckPermByAction     = "/current/check-action"
	UrlPostCheckClientAuth       = "/client/validate"
	UrlPostCheckClientPermByCode = "/client/check-operation"

	KeyJwtUser = "__Auth_Jwt_User__"
)
