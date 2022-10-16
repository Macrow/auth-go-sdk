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

func handleError[T Result](res *req.Response, result *HttpResponse[T], logger logr.Logger, validateResultIsNull bool) error {
	if res == nil {
		logger.Error(ErrInternalError, ErrInternalError.Error())
		return ErrInternalError
	}
	if res.Err != nil {
		logger.Error(res.Err, res.Err.Error())
		return res.Err
	}
	if res.StatusCode != http.StatusOK {
		logger.Error(ErrAuthServerFail, ErrAuthServerFail.Error())
		return ErrAuthServerFail
	}
	if result == nil {
		logger.Error(ErrNoResult, ErrNoResult.Error())
		return ErrNoResult
	}
	if result.Code != CodeSuccess {
		return errors.New(result.Message)
	}
	if validateResultIsNull && result.Result == nil {
		return ErrNoResult
	}
	return nil
}

func (c *HttpClient) initAccessCodeAndRandomKey(f GetHeaderFun, r *req.Request) error {
	if c.Config.AccessCode.Enable {
		if f == nil {
			if len(c.Config.Client.AccessCode) == 0 {
				return ErrAccessCodeEmpty
			}
			r.SetHeader(c.Config.AccessCode.Header, c.Config.Client.AccessCode)
		} else {
			accessCode, err := ExtractAccessCode(f, c.Config.AccessCode.Header)
			if err != nil {
				return err
			}
			r.SetHeader(c.Config.AccessCode.Header, accessCode)
		}
	}
	if c.Config.RandomKey.Enable {
		if f == nil {
			r.SetHeader(c.Config.RandomKey.Header, GenerateRandomKey())
		} else {
			randomKey, err := ExtractRandomKey(f, c.Config.RandomKey.Header)
			if err != nil {
				return err
			}
			r.SetHeader(c.Config.RandomKey.Header, randomKey)
		}
	}
	return nil
}

func (c *HttpClient) initUserToken(f GetHeaderFun, r *req.Request) (string, error) {
	token, err := ExtractUserToken(f, c.Config.User.Header, c.Config.User.HeaderSchema)
	if err != nil && !c.Config.AccessCode.SkipUserTokenCheck {
		return "", err
	}
	r.SetHeader(c.Config.User.Header, c.Config.User.HeaderSchema+" "+token)
	return token, nil
}

func (c *HttpClient) initClientToken(f GetHeaderFun, r *req.Request) (string, error) {
	clientId := ""
	if c.Config.Client.EnableIdAndSecret {
		if f == nil {
			if len(c.Config.Client.Id) == 0 || len(c.Config.Client.Secret) == 0 {
				return clientId, ErrClientIdOrSecretEmpty
			}
			r.SetHeader(c.Config.Client.Header, c.Config.Client.HeaderSchema+" "+GenerateClientToken(c.Config.Client.Id, c.Config.Client.Secret))
		} else {
			clientId, _, schemaAndToken, err := ExtractClientInfoAndToken(f, c.Config.Client.Header, c.Config.Client.HeaderSchema)
			if err != nil {
				return clientId, err
			}
			r.SetHeader(c.Config.Client.Header, schemaAndToken)
		}
	}
	return clientId, nil
}

func (c *HttpClient) CheckAuth(f GetHeaderFun, fulfillCustomAuth bool) (*CheckAuthResult, error) {
	r := c.Agent.Post(UrlPostCheckAuth)
	err := c.initAccessCodeAndRandomKey(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	token, err := c.initUserToken(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	result := &HttpResponse[CheckAuthResult]{}
	res := r.
		SetResult(result).
		SetFormDataAnyType(map[string]interface{}{"fulfillCustomAuth": strconv.FormatBool(fulfillCustomAuth)}).
		Do()
	err = handleError[CheckAuthResult](res, result, c.logger, true)
	if err != nil {
		return nil, err
	}
	if result.Result.User != nil {
		result.Result.User.Token = token
	}
	return result.Result, nil
}

func (c *HttpClient) CheckPermByCode(f GetHeaderFun, code string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) (*CheckPermResult, error) {
	r := c.Agent.Post(UrlPostCheckPermByCode)
	err := c.initAccessCodeAndRandomKey(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	token, err := c.initUserToken(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	result := &HttpResponse[CheckPermResult]{}
	formData := make(map[string]any, 4)
	formData["code"] = code
	formData["fulfillJwt"] = fulfillJwt
	formData["fulfillCustomAuth"] = fulfillCustomAuth
	formData["fulfillCustomPerm"] = fulfillCustomPerm
	res := r.
		SetResult(result).
		SetFormDataAnyType(formData).
		Do()
	err = handleError[CheckPermResult](res, result, c.logger, true)
	if err != nil {
		return nil, err
	}
	if result.Result.User != nil {
		result.Result.User.Token = token
	}
	return result.Result, nil
}

func (c *HttpClient) CheckPermByAction(f GetHeaderFun, service string, method string, path string, fulfillJwt bool, fulfillCustomAuth bool, fulfillCustomPerm bool) (*CheckPermResult, error) {
	r := c.Agent.Post(UrlPostCheckPermByAction)
	err := c.initAccessCodeAndRandomKey(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	token, err := c.initUserToken(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	result := &HttpResponse[CheckPermResult]{}
	formData := make(map[string]any, 6)
	formData["service"] = service
	formData["method"] = method
	formData["path"] = path
	formData["fulfillJwt"] = fulfillJwt
	formData["fulfillCustomAuth"] = fulfillCustomAuth
	formData["fulfillCustomPerm"] = fulfillCustomPerm
	res := r.
		SetResult(result).
		SetFormDataAnyType(formData).
		Do()
	err = handleError[CheckPermResult](res, result, c.logger, true)
	if err != nil {
		return nil, err
	}
	if result.Result.User != nil {
		result.Result.User.Token = token
	}
	return result.Result, nil
}

func (c *HttpClient) CheckClientAuth(f GetHeaderFun) (*CheckClientAuthResult, error) {
	r := c.Agent.Post(UrlPostCheckClientAuth)
	err := c.initAccessCodeAndRandomKey(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	_, err = c.initClientToken(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	result := &HttpResponse[CheckClientAuthResult]{}
	res := r.
		SetResult(result).
		Do()
	err = handleError[CheckClientAuthResult](res, result, c.logger, true)
	if err != nil {
		return nil, err
	}
	return result.Result, nil
}

func (c *HttpClient) CheckClientPermByCode(f GetHeaderFun, code string) (*CheckClientPermResult, error) {
	r := c.Agent.Post(UrlPostCheckClientPermByCode)
	err := c.initAccessCodeAndRandomKey(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	_, err = c.initClientToken(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	result := &HttpResponse[CheckClientPermResult]{}
	formData := make(map[string]any, 1)
	formData["code"] = code
	res := r.
		SetResult(result).
		SetFormDataAnyType(formData).
		Do()
	err = handleError[CheckClientPermResult](res, result, c.logger, true)
	if err != nil {
		return nil, err
	}
	return result.Result, nil
}

func (c *HttpClient) ClientRequest(urlPath string, httpMethod string, queryParam map[string]any, formData map[string]any) (any, error) {
	r := c.Agent.R()
	err := c.initAccessCodeAndRandomKey(nil, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	_, err = c.initClientToken(nil, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	result := &HttpResponse[any]{}

	r.Method = httpMethod
	r.RawURL = urlPath

	res := r.
		SetResult(result).
		SetQueryParamsAnyType(queryParam).
		SetFormDataAnyType(formData).
		Do()
	err = handleError[any](res, result, c.logger, false)
	if err != nil {
		return nil, err
	}
	return result.Result, nil
}
