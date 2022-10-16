package auth

import "errors"

const (
	MsgInternalError         = "服务内部错误"
	MsgAuthServerFail        = "访问鉴权服务失败"
	MsgAccessCodeEmpty       = "未提供访问码"
	MsgRandomKeyEmpty        = "未提供随机码"
	MsgUserTokenEmpty        = "未提供用户令牌"
	MsgClientTokenEmpty      = "未提供客户端令牌"
	MsgClientIdOrSecretEmpty = "未提供客户端Id和秘钥"
	MsgClientTokenFail       = "客户端验证失败"
	MsgJwtErrFormat          = "令牌格式错误"
	MsgJwtErrVersion         = "令牌版本错误"
	MsgNoResult              = "解析返回结果错误"
	MsgRateLimit             = "访问过于频繁"
	MsgAuthFail              = "身份验证失败"
	MsgPermFail              = "权限验证失败"
)

var (
	ErrInternalError         = errors.New(MsgInternalError)
	ErrAuthServerFail        = errors.New(MsgAuthServerFail)
	ErrAccessCodeEmpty       = errors.New(MsgAccessCodeEmpty)
	ErrRandomKeyEmpty        = errors.New(MsgRandomKeyEmpty)
	ErrUserTokenEmpty        = errors.New(MsgUserTokenEmpty)
	ErrClientTokenEmpty      = errors.New(MsgClientTokenEmpty)
	ErrClientIdOrSecretEmpty = errors.New(MsgClientIdOrSecretEmpty)
	ErrClientTokenFail       = errors.New(MsgClientTokenFail)
	ErrJwtErrFormat          = errors.New(MsgJwtErrFormat)
	ErrJwtErrVersion         = errors.New(MsgJwtErrVersion)
	ErrNoResult              = errors.New(MsgNoResult)
	ErrRateLimit             = errors.New(MsgRateLimit)
	ErrAuthFail              = errors.New(MsgAuthFail)
	ErrPermFail              = errors.New(MsgPermFail)
)
