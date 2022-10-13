package auth

const (
	DefaultCacheSplitter = "::"
	// DefaultIssuer 默认签发人
	DefaultIssuer = "auth-go-sdk"
	// DefaultJwtExpireInMinutes 缓存失效时间默认为365天
	DefaultJwtExpireInMinutes = 60 * 24 * 365
	DefaultHeaderRandomKey    = "Random-Key"
	DefaultHeaderAccessCode   = "Access-Code"
	DefaultHeaderUserToken    = "Authorization"
	DefaultHeaderClientToken  = "Client-Authorization"
	DefaultHeaderSchema       = "Bearer"
	DefaultMetaBy             = "id"

	JwtTokenClaimsId       string = "id"
	JwtTokenClaimsName     string = "name"
	JwtTokenClaimsKind     string = "kind"
	JwtTokenClaimsDeviceId string = "did"
	JwtTokenClaimsIssuer   string = "iss"
	JwtTokenClaimsIssueAt  string = "iat"
	JwtTokenClaimsExpireAt string = "exp"

	MsgAuthServerFail        = "访问鉴权服务器失败"
	MsgUserTokenEmpty        = "未提供用户令牌"
	MsgClientTokenEmpty      = "未提供客户端令牌"
	MsgClientIdOrSecretEmpty = "未提供客户端Id和秘钥"
	MsgUserTokenFail         = "用户令牌错误或失效"
	MsgClientTokenFail       = "客户端验证失败"
	MsgAuthFail              = "身份验证失败"
	MsgPermFail              = "权限验证失败"
	MsgInternalError         = "服务内部错误"

	UrlGetCheckAuth              = "/current/jwt"
	UrlPostCheckPermByCode       = "/current/check-operation"
	UrlPostCheckPermByAction     = "/current/check-action"
	UrlGetCheckClientAuth        = "/client/validate"
	UrlPostCheckClientPermByCode = "/client/check-operation"

	KeyJwtUser = "__Auth_Jwt_User__"
)
