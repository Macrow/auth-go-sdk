package auth

import (
	"context"
	"errors"
	"github.com/Macrow/auth-go-sdk/config"
	"github.com/go-logr/logr"
	"github.com/imroc/req/v3"
	"net/http"
	"strconv"
	"strings"
)

type HttpClient struct {
	Config *config.HttpClientConfig
	Agent  *req.Client
	logger logr.Logger
	ctx    context.Context
}

func handleErrorAndGetResult[T Result](res *req.Response, logger logr.Logger, result *HttpResponse[T], defaultRes *T) T {
	if defaultRes == nil {
		logger.Error(nil, "默认返回数据错误")
	}
	if res.Err != nil {
		logger.Error(res.Err, MsgAuthServerFail)
		return *defaultRes
	}
	if res.StatusCode != http.StatusOK {
		logger.Error(nil, MsgAuthServerFail)
		return *defaultRes
	}
	if result == nil {
		logger.Error(nil, "解析返回结果错误")
	}
	if result.Code != 0 {
		logger.Error(nil, result.Message)
		return *defaultRes
	}
	return result.Result
}

func (c *HttpClient) initAccessCodeAndRandomKey(req *http.Request) error {
	if c.Config.AccessCode.Enable {
		if req == nil {
			if len(c.Config.Client.AccessCode) == 0 {
				return errors.New(MsgClientAccessCodeEmpty)
			}
			c.Agent.SetCommonHeader(c.Config.AccessCode.Header, c.Config.Client.AccessCode)
		} else {
			c.Agent.SetCommonHeader(c.Config.AccessCode.Header, req.Header.Get(c.Config.AccessCode.Header))
		}
	}
	if c.Config.RandomKey.Enable {
		if req == nil {
			c.Agent.SetCommonHeader(c.Config.RandomKey.Header, GenerateRandomKey())
		} else {
			c.Agent.SetCommonHeader(c.Config.RandomKey.Header, req.Header.Get(c.Config.RandomKey.Header))
		}
	}
	return nil
}

func (c *HttpClient) initUserToken(req *http.Request) (string, error) {
	token, err := c.extractUserToken(req)
	if err != nil && !c.Config.AccessCode.SkipUserTokenCheck {
		return "", err
	}
	c.Agent.SetCommonHeader(c.Config.User.Header, c.Config.User.HeaderSchema+" "+token)
	return token, nil
}

func (c *HttpClient) initClientToken(req *http.Request) (string, error) {
	clientId := ""
	if c.Config.Client.EnableIdAndSecret {
		if req == nil {
			if len(c.Config.Client.Id) == 0 || len(c.Config.Client.Secret) == 0 {
				return clientId, errors.New(MsgClientIdOrSecretEmpty)
			}
			c.Agent.SetCommonHeader(c.Config.Client.Header, c.Config.Client.HeaderSchema+" "+GenerateClientToken(c.Config.Client.Id, c.Config.Client.Secret))
		} else {
			schemaAndToken := req.Header.Get(c.Config.Client.Header)
			if len(schemaAndToken) > 0 && strings.HasPrefix(schemaAndToken, c.Config.Client.HeaderSchema+" ") {
				clientId, _, err := ParseClientToken(schemaAndToken[len(c.Config.User.HeaderSchema)+1:])
				if err != nil {
					return clientId, err
				}
				c.Agent.SetCommonHeader(c.Config.Client.Header, schemaAndToken)
			} else {
				return clientId, errors.New(MsgClientTokenEmpty)
			}
		}
	}
	return clientId, nil
}

func (c *HttpClient) extractUserToken(req *http.Request) (string, error) {
	schemaAndToken := req.Header.Get(c.Config.User.Header)
	if len(schemaAndToken) == 0 {
		return "", errors.New(MsgUserTokenEmpty)
	}
	if !strings.HasPrefix(schemaAndToken, c.Config.User.HeaderSchema+" ") {
		return "", errors.New(MsgUserTokenEmpty)
	}
	return schemaAndToken[len(c.Config.User.HeaderSchema)+1:], nil
}

func (c *HttpClient) checkAuth(req *http.Request, fulfillCustomAuth bool) CheckAuthResult {
	errRes := CheckAuthResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
	}
	err := c.initAccessCodeAndRandomKey(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	token, err := c.initUserToken(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	result := &HttpResponse[CheckAuthResult]{}
	res := c.Agent.
		Post(UrlPostCheckAuth).
		SetResult(result).
		SetQueryParam("fulfillCustomAuth", strconv.FormatBool(fulfillCustomAuth)).
		Do()
	r := handleErrorAndGetResult[CheckAuthResult](res, c.logger, result, &errRes)
	r.User.Token = token
	c.ctx = req.Context()
	c.ctx = context.WithValue(c.ctx, KeyJwtUser, r.User)
	if r.CustomAuth != nil {
		c.ctx = context.WithValue(c.ctx, KeyCustomAuth, r.CustomAuth)
	}
	return r
}

func (c *HttpClient) checkPermByCode(req *http.Request, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) CheckPermResult {
	errRes := CheckPermResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
		CustomPerm:       nil,
	}
	err := c.initAccessCodeAndRandomKey(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	token, err := c.initUserToken(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	result := &HttpResponse[CheckPermResult]{}
	formData := make(map[string]string, 4)
	formData["code"] = code
	formData["fulfillJwt"] = strconv.FormatBool(fulfillJwt)
	formData["fulfillCustomAuth"] = strconv.FormatBool(fulfillCustomAuth)
	formData["fulfillCustomPerm"] = strconv.FormatBool(fulfillCustomPerm)
	res := c.Agent.
		Post(UrlPostCheckPermByCode).
		SetResult(result).
		SetFormData(formData).
		Do()
	r := handleErrorAndGetResult[CheckPermResult](res, c.logger, result, &errRes)
	r.User.Token = token
	c.ctx = req.Context()
	c.ctx = context.WithValue(c.ctx, KeyJwtUser, r.User)
	if r.CustomAuth != nil {
		c.ctx = context.WithValue(c.ctx, KeyCustomAuth, r.CustomAuth)
	}
	if r.CustomPerm != nil {
		c.ctx = context.WithValue(c.ctx, KeyCustomPerm, r.CustomPerm)
	}
	return r
}

func (c *HttpClient) checkPermByAction(req *http.Request, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) CheckPermResult {
	errRes := CheckPermResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
		CustomPerm:       nil,
	}
	err := c.initAccessCodeAndRandomKey(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	token, err := c.initUserToken(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	result := &HttpResponse[CheckPermResult]{}
	formData := make(map[string]string, 6)
	formData["service"] = service
	formData["method"] = method
	formData["path"] = path
	formData["fulfillJwt"] = strconv.FormatBool(fulfillJwt)
	formData["fulfillCustomAuth"] = strconv.FormatBool(fulfillCustomAuth)
	formData["fulfillCustomPerm"] = strconv.FormatBool(fulfillCustomPerm)
	res := c.Agent.
		Post(UrlPostCheckPermByAction).
		SetResult(result).
		SetFormData(formData).
		Do()
	r := handleErrorAndGetResult[CheckPermResult](res, c.logger, result, &errRes)
	r.User.Token = token
	c.ctx = req.Context()
	c.ctx = context.WithValue(c.ctx, KeyJwtUser, r.User)
	if r.CustomAuth != nil {
		c.ctx = context.WithValue(c.ctx, KeyCustomAuth, r.CustomAuth)
	}
	if r.CustomPerm != nil {
		c.ctx = context.WithValue(c.ctx, KeyCustomPerm, r.CustomPerm)
	}
	return r
}

func (c *HttpClient) checkClientAuth(req *http.Request) CheckClientAuthResult {
	errRes := CheckClientAuthResult{
		ClientAuthOk: false,
	}
	err := c.initAccessCodeAndRandomKey(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	clientId, err := c.initClientToken(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	result := &HttpResponse[CheckClientAuthResult]{}
	res := c.Agent.
		Post(UrlPostCheckClientAuth).
		SetResult(result).
		Do()
	r := handleErrorAndGetResult[CheckClientAuthResult](res, c.logger, result, &errRes)
	c.ctx = req.Context()
	c.ctx = context.WithValue(c.ctx, KeyClientId, &clientId)
	return r
}

func (c *HttpClient) checkClientPermByCode(req *http.Request, code string) CheckClientPermResult {
	errRes := CheckClientPermResult{
		ClientPermOk: false,
	}
	err := c.initAccessCodeAndRandomKey(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	clientId, err := c.initClientToken(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	result := &HttpResponse[CheckClientPermResult]{}
	formData := make(map[string]string, 1)
	formData["code"] = code
	res := c.Agent.
		Post(UrlPostCheckClientPermByCode).
		SetResult(result).
		SetFormData(formData).
		Do()
	r := handleErrorAndGetResult[CheckClientPermResult](res, c.logger, result, &errRes)
	c.ctx = req.Context()
	c.ctx = context.WithValue(c.ctx, KeyClientId, &clientId)
	return r
}

func (c *HttpClient) Request(url string, queryParam map[string]string, formData map[string]string) HttpResponse[interface{}] {
	errRes := HttpResponse[interface{}]{
		Code:    1,
		Message: MsgInternalError,
		Success: false,
		Result:  nil,
	}
	err := c.initAccessCodeAndRandomKey(nil)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	_, err = c.initClientToken(nil)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	result := &HttpResponse[interface{}]{}
	res := c.Agent.
		Post(url).
		SetResult(result).
		SetQueryParams(queryParam).
		SetFormData(formData).
		Do()

	if res.Err != nil {
		c.logger.Error(res.Err, MsgServerFail)
		errRes.Message = res.Err.Error()
		return errRes
	}
	if res.StatusCode != http.StatusOK {
		c.logger.Error(nil, MsgServerFail)
		errRes.Message = res.Err.Error()
		return errRes
	}
	if result == nil {
		c.logger.Error(nil, "解析返回结果错误")
	}

	return *result
}

func (c *HttpClient) GetJwtUser() *JwtUser {
	if c.ctx == nil {
		return nil
	}
	return c.ctx.Value(KeyJwtUser).(*JwtUser)
}

func (c *HttpClient) GetCustomAuth() interface{} {
	if c.ctx == nil {
		return nil
	}
	return c.ctx.Value(KeyCustomAuth)
}

func (c *HttpClient) GetCustomPerm() interface{} {
	if c.ctx == nil {
		return nil
	}
	return c.ctx.Value(KeyCustomPerm)
}

func (c *HttpClient) GetClientId() *string {
	if c.ctx == nil {
		return nil
	}
	return c.ctx.Value(KeyClientId).(*string)
}
