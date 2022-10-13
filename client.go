package auth

import (
	"github.com/go-logr/logr"
	"github.com/imroc/req/v3"
	"net/http"
	"strconv"
	"strings"
)

type Client struct {
	config *HttpClientConfig
	agent  *req.Client
	logger logr.Logger
}

func handleErrorAndGetResult[T Result](res *req.Response, logger logr.Logger, result *HttpResponse[T], defaultRes *T) T {
	if defaultRes == nil {
		logger.Error(nil, "默认返回数据错误")
	}
	if result == nil {
		logger.Error(nil, "获取鉴权信息错误")
	}
	if res.Err != nil {
		logger.Error(res.Err, MsgAuthServerFail)
		return *defaultRes
	}
	if res.StatusCode != http.StatusOK {
		logger.Error(nil, MsgAuthServerFail)
		return *defaultRes
	}
	if result.Code != 0 {
		logger.Error(nil, result.Message)
		return *defaultRes
	}
	return result.Result
}

func (c *Client) initAccessCodeAndRandomKeyForAgent(req *http.Request) *req.Client {
	if c.config.AccessCode.Enable {
		c.agent.SetCommonHeader(c.config.AccessCode.Header, req.Header.Get(c.config.AccessCode.Header))
	}
	if c.config.RandomKey.Enable {
		if req == nil {
			c.agent.SetCommonHeader(c.config.RandomKey.Header, GenerateRandomKey())
		} else {
			c.agent.SetCommonHeader(c.config.RandomKey.Header, req.Header.Get(c.config.RandomKey.Header))
		}
	}
	return c.agent
}

func (c *Client) initClientTokenForAgent(req *http.Request) (*req.Client, error) {
	if c.config.Client.EnableIdAndSecret {
		if req == nil {
			c.agent.SetCommonHeader(c.config.Client.Header, c.config.Client.HeaderSchema+" "+GenerateClientToken(c.config.Client.Id, c.config.Client.Secret))
		} else {
			schemaAndToken := req.Header.Get(c.config.User.Header)
			if len(schemaAndToken) > 0 && strings.HasPrefix(schemaAndToken, c.config.User.HeaderSchema+" ") {
				_, _, err := ParseClientToken(schemaAndToken[len(c.config.User.HeaderSchema)+1:])
				if err != nil {
					return nil, err
				}
				c.agent.SetCommonHeader(c.config.Client.Header, schemaAndToken)
			}
		}
	}
	return c.agent, nil
}

func (c *Client) extractUserToken(req *http.Request) (string, error) {
	schemaAndToken := req.Header.Get(c.config.User.Header)
	if len(schemaAndToken) == 0 {
		return "", &UserTokenEmptyError{}
	}
	if !strings.HasPrefix(schemaAndToken, c.config.User.HeaderSchema+" ") {
		return "", &UserTokenEmptyError{}
	}
	return schemaAndToken[len(c.config.User.HeaderSchema)+1:], nil
}

func (c *Client) checkAuth(req *http.Request, fulfillCustomAuth bool) CheckAuthResult {
	errRes := CheckAuthResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
	}
	token, err := c.extractUserToken(req)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	result := &HttpResponse[CheckAuthResult]{}
	res := c.initAccessCodeAndRandomKeyForAgent(req).
		SetCommonHeader(c.config.User.Header, c.config.User.HeaderSchema+" "+token).
		Get(UrlGetCheckAuth).
		SetResult(result).
		SetQueryParam("fulfillCustomAuth", strconv.FormatBool(fulfillCustomAuth)).
		Do()
	r := handleErrorAndGetResult[CheckAuthResult](res, c.logger, result, &errRes)
	r.User.Token = token
	return r
}

func (c *Client) checkPermByCode(req *http.Request, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) CheckPermResult {
	errRes := CheckPermResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
		CustomPerm:       nil,
	}
	token, err := c.extractUserToken(req)
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
	res := c.agent.
		SetCommonHeader(c.config.User.Header, c.config.User.HeaderSchema+" "+token).
		Post(UrlPostCheckPermByCode).
		SetResult(result).
		SetFormData(formData).
		Do()
	r := handleErrorAndGetResult[CheckPermResult](res, c.logger, result, &errRes)
	r.User.Token = token
	return r
}

func (c *Client) checkPermByAction(req *http.Request, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) CheckPermResult {
	errRes := CheckPermResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
		CustomPerm:       nil,
	}
	token, err := c.extractUserToken(req)
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
	res := c.agent.
		SetCommonHeader(c.config.User.Header, c.config.User.HeaderSchema+" "+token).
		Post(UrlPostCheckPermByCode).
		SetResult(result).
		SetFormData(formData).
		Do()
	r := handleErrorAndGetResult[CheckPermResult](res, c.logger, result, &errRes)
	r.User.Token = token
	return r
}

func (c *Client) checkClientAuth(req *http.Request) CheckClientAuthResult {
	errRes := CheckClientAuthResult{
		ClientAuthOk: false,
	}
	result := &HttpResponse[CheckClientAuthResult]{}
	agent, err := c.initClientTokenForAgent(req)
	if err != nil {
		return errRes
	}
	res := agent.
		Get(UrlPostCheckPermByCode).
		SetResult(result).
		Do()
	return handleErrorAndGetResult[CheckClientAuthResult](res, c.logger, result, &errRes)
}

func (c *Client) checkClientPermByCode(req *http.Request, code string) CheckClientPermResult {
	errRes := CheckClientPermResult{
		ClientPermOk: false,
	}
	result := &HttpResponse[CheckClientPermResult]{}
	formData := make(map[string]string, 1)
	formData["code"] = code
	agent, err := c.initClientTokenForAgent(req)
	if err != nil {
		return errRes
	}
	res := agent.
		Post(UrlPostCheckPermByCode).
		SetResult(result).
		SetFormData(formData).
		Do()
	return handleErrorAndGetResult[CheckClientPermResult](res, c.logger, result, &errRes)
}
