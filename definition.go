package auth

import (
	"net/http"
)

type CheckAuthResult struct {
	SkippedAuthCheck bool        `json:"skippedAuthCheck,omitempty"`
	User             *JwtUser    `json:"user,omitempty"`
	CustomAuth       interface{} `json:"customAuth,omitempty"`
}

type CheckPermResult struct {
	SkippedAuthCheck bool        `json:"skippedAuthCheck,omitempty"`
	User             *JwtUser    `json:"user,omitempty"`
	CustomAuth       interface{} `json:"customAuth,omitempty"`
	CustomPerm       interface{} `json:"customPerm,omitempty"`
}

type CheckClientAuthResult struct {
	ClientAuthOk bool `json:"clientAuthOk,omitempty"`
}

type CheckClientPermResult struct {
	ClientPermOk bool `json:"clientPermOk,omitempty"`
}

type Result interface {
	CheckAuthResult | CheckPermResult | CheckClientAuthResult | CheckClientPermResult
}

type HttpResponse[T Result] struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
	Result  T      `json:"result,omitempty"`
}

type UserTokenEmptyError struct{}
type ClientTokenEmptyError struct{}
type UserTokenFailError struct{}
type ClientTokenFailError struct{}
type NoAuthError struct{}
type NoPermError struct{}

func (r *UserTokenEmptyError) Error() string {
	return MsgUserTokenEmpty
}

func (r *ClientTokenEmptyError) Error() string {
	return MsgClientTokenEmpty
}

func (r *UserTokenFailError) Error() string {
	return MsgUserTokenFail
}

func (r *ClientTokenFailError) Error() string {
	return MsgClientTokenFail
}

func (r *NoAuthError) Error() string {
	return MsgAuthFail
}

func (r *NoPermError) Error() string {
	return MsgPermFail
}

// IAuthCheck 实现本地验证服务，所有方法都不抛出异常，如果权限检查失败，jwtUser返回nil
type IAuthCheck interface {
	checkAuth(userToken string, fulfillCustomAuth bool) CheckAuthResult
	checkPermByCode(userToken string, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) CheckPermResult
	checkPermByAction(userToken string, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) CheckPermResult
	checkClientAuth(clientId string, clientSecret string) CheckClientAuthResult
	checkClientPermByCode(clientId string, clientSecret string, code string) CheckClientPermResult
}

// IAuthClient 实现远程调用验证，所有方法都不抛出异常，如果权限检查失败，jwtUser返回nil
type IAuthClient interface {
	checkAuth(req *http.Request, fulfillCustomAuth bool) CheckAuthResult
	checkPermByCode(req *http.Request, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) CheckPermResult
	checkPermByAction(req *http.Request, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) CheckPermResult
	checkClientAuth(req *http.Request) CheckClientAuthResult
	checkClientPermByCode(req *http.Request, code string) CheckClientPermResult
}
