package auth

const (
	CodeSuccess              = 0
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

	UrlPostCheckAuth             = "/current/jwt"
	UrlPostCheckPermByCode       = "/current/check-operation"
	UrlPostCheckPermByAction     = "/current/check-action"
	UrlPostCheckClientAuth       = "/client/validate"
	UrlPostCheckClientPermByCode = "/client/check-operation"

	KeySkipAuthCheck = "__SkipAuthCheck__"
	KeyJwtUser       = "__JwtUser__"
	KeyCustomAuth    = "__CustomAuth__"
	KeyCustomPerm    = "__CustomPerm__"
	KeyClientId      = "__ClientId__"
	KeyMetaBy        = "__MetaBy__"
)
