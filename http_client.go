package auth

import (
	"errors"
	"github.com/go-logr/logr"
	"github.com/imroc/req/v3"
	"net/http"
	"strconv"
)

type HttpClient struct {
	Config *HttpClientConfig
	Agent  *req.Client
	logger logr.Logger
}

func handleErrorAndGetResult[T Result](res *req.Response, logger logr.Logger, result *HttpResponse[T], defaultRes *T) *T {
	if defaultRes == nil {
		logger.Error(NoAuthError, "默认返回数据错误")
	}
	if res.Err != nil {
		logger.Error(res.Err, MsgAuthServerFail)
		return defaultRes
	}
	if res.StatusCode != http.StatusOK {
		logger.Error(NoAuthError, MsgAuthServerFail)
		return defaultRes
	}
	if result == nil {
		logger.Error(NoAuthError, "解析返回结果错误")
	}
	if result.Code != 0 {
		logger.Error(NoAuthError, result.Message)
		return defaultRes
	}
	return &result.Result
}

func (c *HttpClient) initAccessCodeAndRandomKey(f GetHeaderFun) error {
	if c.Config.AccessCode.Enable {
		if f == nil {
			if len(c.Config.Client.AccessCode) == 0 {
				return errors.New(MsgClientAccessCodeEmpty)
			}
			c.Agent.SetCommonHeader(c.Config.AccessCode.Header, c.Config.Client.AccessCode)
		} else {
			c.Agent.SetCommonHeader(c.Config.AccessCode.Header, ExtractCommonHeader(f, c.Config.AccessCode.Header))
		}
	}
	if c.Config.RandomKey.Enable {
		if f == nil {
			c.Agent.SetCommonHeader(c.Config.RandomKey.Header, GenerateRandomKey())
		} else {
			c.Agent.SetCommonHeader(c.Config.RandomKey.Header, ExtractCommonHeader(f, c.Config.RandomKey.Header))
		}
	}
	return nil
}

func (c *HttpClient) initUserToken(f GetHeaderFun) (string, error) {
	token, err := ExtractUserToken(f, c.Config.User.Header, c.Config.User.HeaderSchema)
	if err != nil && !c.Config.AccessCode.SkipUserTokenCheck {
		return "", err
	}
	c.Agent.SetCommonHeader(c.Config.User.Header, c.Config.User.HeaderSchema+" "+token)
	return token, nil
}

func (c *HttpClient) initClientToken(f GetHeaderFun) (string, error) {
	clientId := ""
	if c.Config.Client.EnableIdAndSecret {
		if f == nil {
			if len(c.Config.Client.Id) == 0 || len(c.Config.Client.Secret) == 0 {
				return clientId, errors.New(MsgClientIdOrSecretEmpty)
			}
			c.Agent.SetCommonHeader(c.Config.Client.Header, c.Config.Client.HeaderSchema+" "+GenerateClientToken(c.Config.Client.Id, c.Config.Client.Secret))
		} else {
			clientId, _, schemaAndToken, err := ExtractClientInfoAndToken(f, c.Config.Client.Header, c.Config.Client.HeaderSchema)
			if err != nil {
				return clientId, err
			}
			c.Agent.SetCommonHeader(c.Config.Client.Header, schemaAndToken)
		}
	}
	return clientId, nil
}

func (c *HttpClient) CheckAuth(f GetHeaderFun, fulfillCustomAuth bool) *CheckAuthResult {
	errRes := &CheckAuthResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
	}
	err := c.initAccessCodeAndRandomKey(f)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	token, err := c.initUserToken(f)
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
	handledRes := handleErrorAndGetResult[CheckAuthResult](res, c.logger, result, errRes)
	if handledRes.User != nil {
		handledRes.User.Token = token
	}
	return handledRes
}

func (c *HttpClient) CheckPermByCode(f GetHeaderFun, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) *CheckPermResult {
	errRes := &CheckPermResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
		CustomPerm:       nil,
	}
	err := c.initAccessCodeAndRandomKey(f)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	token, err := c.initUserToken(f)
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
	handledRes := handleErrorAndGetResult[CheckPermResult](res, c.logger, result, errRes)
	if handledRes.User != nil {
		handledRes.User.Token = token
	}
	return handledRes
}

func (c *HttpClient) CheckPermByAction(f GetHeaderFun, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) *CheckPermResult {
	errRes := &CheckPermResult{
		SkippedAuthCheck: false,
		User:             nil,
		CustomAuth:       nil,
		CustomPerm:       nil,
	}
	err := c.initAccessCodeAndRandomKey(f)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	token, err := c.initUserToken(f)
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
	handledRes := handleErrorAndGetResult[CheckPermResult](res, c.logger, result, errRes)
	if handledRes.User != nil {
		handledRes.User.Token = token
	}
	return handledRes
}

func (c *HttpClient) CheckClientAuth(f GetHeaderFun) *CheckClientAuthResult {
	errRes := &CheckClientAuthResult{
		ClientAuthOk: false,
	}
	err := c.initAccessCodeAndRandomKey(f)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	_, err = c.initClientToken(f)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	result := &HttpResponse[CheckClientAuthResult]{}
	res := c.Agent.
		Post(UrlPostCheckClientAuth).
		SetResult(result).
		Do()
	return handleErrorAndGetResult[CheckClientAuthResult](res, c.logger, result, errRes)
}

func (c *HttpClient) CheckClientPermByCode(f GetHeaderFun, code string) *CheckClientPermResult {
	errRes := &CheckClientPermResult{
		ClientPermOk: false,
	}
	err := c.initAccessCodeAndRandomKey(f)
	if err != nil {
		c.logger.Error(err, err.Error())
		return errRes
	}
	_, err = c.initClientToken(f)
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
	return handleErrorAndGetResult[CheckClientPermResult](res, c.logger, result, errRes)
}

func (c *HttpClient) ruest(url string, queryParam map[string]string, formData map[string]string) HttpResponse[interface{}] {
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
		c.logger.Error(NoAuthError, MsgServerFail)
		errRes.Message = res.Err.Error()
		return errRes
	}
	if result == nil {
		c.logger.Error(NoAuthError, "解析返回结果错误")
	}
	return *result
}
