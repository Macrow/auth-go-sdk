package auth

import "net/http"

// IAuthCheck 实现本地验证服务，所有方法都不抛出异常，如果权限检查失败，jwtUser返回nil
type IAuthCheck interface {
	IsAccessCodeOk(code string) (bool, error)
	IsRandomKeyOk(key string) (bool, error)
	CheckAuth(userToken string, fulfillCustomAuth bool) (*CheckAuthResult, error)
	CheckPermByCode(userToken string, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) (*CheckPermResult, error)
	CheckPermByAction(userToken string, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) (CheckPermResult, error)
	CheckClientAuth(clientId string, clientSecret string) (*CheckClientAuthResult, error)
	CheckClientPermByCode(clientId string, clientSecret string, code string) (*CheckClientPermResult, error)
}

// IAuthClient 实现远程调用验证，所有方法都不抛出异常，如果权限检查失败，jwtUser返回nil
type IAuthClient interface {
	CheckAuth(req *http.Request, fulfillCustomAuth bool) *CheckAuthResult
	CheckPermByCode(req *http.Request, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) *CheckPermResult
	CheckPermByAction(req *http.Request, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) *CheckPermResult
	CheckClientAuth(req *http.Request) *CheckClientAuthResult
	CheckClientPermByCode(req *http.Request, code string) *CheckClientPermResult
}
