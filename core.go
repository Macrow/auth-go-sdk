package auth

import "net/http"

// IAuthCheck 实现本地验证服务，所有方法都不抛出异常，如果权限检查失败，jwtUser返回nil
type IAuthCheck interface {
	isAccessCodeOk(code string) bool
	isRandomKeyOk(key string) bool
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
