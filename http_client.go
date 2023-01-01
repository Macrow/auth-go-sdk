package auth

import (
	"errors"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/imroc/req/v3"
	"net/http"
	"strconv"
)

type HttpClient struct {
	Config  *HttpClientConfig
	Agent   *req.Client
	AesUtil *AesUtil
	logger  logr.Logger
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

func (c *HttpClient) initTraceLog(f GetHeaderFun, r *req.Request) error {
	if c.Config.EnableTraceLog {
		var traceId string
		if f == nil {
			traceId = uuid.New().String()
		} else {
			traceId = f(TraceId)
			if len(traceId) == 0 {
				traceId = uuid.New().String()
			}
		}
		r.SetHeader(TraceId, traceId)
	}
	return nil
}

func (c *HttpClient) initAccessCodeAndRandomKey(f GetHeaderFun, r *req.Request) error {
	if c.Config.AccessCode.Enable {
		if f == nil {
			if len(c.Config.Client.AccessCode) == 0 {
				return ErrAccessCodeEmpty
			}
			if c.Config.AccessCode.EncryptContent {
				accessCode, err := c.AesUtil.encrypt(c.Config.Client.AccessCode)
				if err != nil {
					panic(err)
				}
				r.SetHeader(c.Config.AccessCode.Header, accessCode)
			} else {
				r.SetHeader(c.Config.AccessCode.Header, c.Config.Client.AccessCode)
			}
		} else {
			accessCode, err := ExtractAccessCode(f, c.Config.AccessCode.Header, c.Config.AccessCode.EncryptContent, c.AesUtil, c.logger)
			if err != nil {
				return err
			}
			if c.Config.AccessCode.EncryptContent {
				accessCode, err = c.AesUtil.encrypt(c.Config.Client.AccessCode)
				if err != nil {
					panic(err)
				}
				r.SetHeader(c.Config.AccessCode.Header, accessCode)
			} else {
				r.SetHeader(c.Config.AccessCode.Header, accessCode)
			}
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
			var clientToken string
			var err error
			if c.Config.Client.EncryptContent {
				clientToken, err = GenerateClientToken(c.Config.Client.Id, c.Config.Client.Secret, c.AesUtil)
			} else {
				clientToken, err = GenerateClientToken(c.Config.Client.Id, c.Config.Client.Secret, nil)
			}
			if err != nil {
				panic(err)
			}
			r.SetHeader(c.Config.Client.Header, c.Config.Client.HeaderSchema+" "+clientToken)
		} else {
			clientId, clientSecret, schemaAndToken, err := ExtractClientInfoAndToken(f, c.Config.Client.Header, c.Config.Client.HeaderSchema, c.Config.Client.EncryptContent, c.AesUtil, c.logger)
			if err != nil {
				return clientId, err
			}
			if c.Config.Client.EncryptContent {
				schemaAndToken, err = GenerateClientToken(clientId, clientSecret, c.AesUtil)
				if err != nil {
					panic(err)
				}
			}
			r.SetHeader(c.Config.Client.Header, schemaAndToken)
		}
	}
	return clientId, nil
}

func (c *HttpClient) CheckAuth(f GetHeaderFun, fulfillCustomAuth bool) (*CheckAuthResult, error) {
	r := c.Agent.Post(UrlPostCheckAuth)
	err := c.initTraceLog(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	err = c.initAccessCodeAndRandomKey(f, r)
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
	err := c.initTraceLog(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	err = c.initAccessCodeAndRandomKey(f, r)
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
	err := c.initTraceLog(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	err = c.initAccessCodeAndRandomKey(f, r)
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
	err := c.initTraceLog(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	err = c.initAccessCodeAndRandomKey(f, r)
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
	err := c.initTraceLog(f, r)
	if err != nil {
		c.logger.Error(err, err.Error())
		return nil, err
	}
	err = c.initAccessCodeAndRandomKey(f, r)
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

func (c *HttpClient) ClientRequest(traceId string, urlPath string, httpMethod string, queryParam map[string]any, formData map[string]any) (any, error) {
	r := c.Agent.R()
	var err error
	if len(traceId) == 0 {
		traceId = uuid.New().String()
	}
	r.SetHeader(TraceId, traceId)
	err = c.initAccessCodeAndRandomKey(nil, r)
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
