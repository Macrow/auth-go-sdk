package auth

import (
	"context"
	"net/http"
)

// IAuthCheck 实现本地验证服务，所有方法都不抛出异常，如果权限检查失败，jwtUser返回nil
type IAuthCheck interface {
	IsAccessCodeOk(ctx context.Context, code string) (bool, error)
	IsRandomKeyOk(ctx context.Context, key string) (bool, error)
	CheckAuth(ctx context.Context, userToken string, fulfillCustomAuth bool) (*CheckAuthResult, error)
	CheckPermByCode(ctx context.Context, userToken string, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) (*CheckPermResult, error)
	CheckPermByAction(ctx context.Context, userToken string, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) (CheckPermResult, error)
	CheckClientAuth(ctx context.Context, clientId string, clientSecret string) (*CheckClientAuthResult, error)
	CheckClientPermByCode(ctx context.Context, clientId string, clientSecret string, code string) (*CheckClientPermResult, error)
}

// IAuthClient 实现远程调用验证，所有方法都不抛出异常，如果权限检查失败，jwtUser返回nil
type IAuthClient interface {
	CheckAuth(r *http.Request, fulfillCustomAuth bool) *CheckAuthResult
	CheckPermByCode(r *http.Request, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) *CheckPermResult
	CheckPermByAction(r *http.Request, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) *CheckPermResult
	CheckClientAuth(r *http.Request) *CheckClientAuthResult
	CheckClientPermByCode(r *http.Request, code string) *CheckClientPermResult
}
