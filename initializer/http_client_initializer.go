package initializer

import (
	"github.com/Macrow/auth-go-sdk"
	"github.com/Macrow/auth-go-sdk/config"
	"github.com/imroc/req/v3"
)

type ClientOption func(*auth.HttpClient)

func WithBasicConfig(config config.Service) ClientOption {
	return func(client *auth.HttpClient) {
		baseUrl := auth.GetNonEmptyValue(config.AuthServiceBaseUrl)
		client.Config.Service.AuthServiceBaseUrl = baseUrl
		client.Config.Service.CurrentServiceName = auth.GetNonEmptyValue(config.CurrentServiceName)
		client.Agent.SetBaseURL(baseUrl)
	}
}

func WithAccessCodeConfig(config config.AccessCode) ClientOption {
	return func(client *auth.HttpClient) {
		client.Config.AccessCode.Enable = config.Enable
		client.Config.AccessCode.SkipUserTokenCheck = config.SkipUserTokenCheck
		client.Config.AccessCode.Header = auth.GetNonEmptyValueWithBackup(config.Header, auth.DefaultHeaderAccessCode)
	}
}

func WithRandomKeyConfig(config config.RandomKey) ClientOption {
	return func(client *auth.HttpClient) {
		client.Config.RandomKey.Enable = config.Enable
		client.Config.RandomKey.Header = auth.GetNonEmptyValueWithBackup(config.Header, auth.DefaultHeaderRandomKey)
	}
}

func WithUserConfig(config config.User) ClientOption {
	return func(client *auth.HttpClient) {
		client.Config.User.Header = auth.GetNonEmptyValueWithBackup(config.Header, auth.DefaultHeaderUserToken)
		client.Config.User.HeaderSchema = auth.GetNonEmptyValueWithBackup(config.HeaderSchema, auth.DefaultHeaderSchema)
	}
}

func WithClientConfig(config config.Client) ClientOption {
	return func(client *auth.HttpClient) {
		client.Config.Client.Id = config.Id
		client.Config.Client.Secret = config.Secret
		client.Config.Client.EnableIdAndSecret = config.EnableIdAndSecret
		client.Config.Client.AccessCode = config.AccessCode
		client.Config.Client.Header = auth.GetNonEmptyValueWithBackup(config.Header, auth.DefaultHeaderClientToken)
		client.Config.Client.HeaderSchema = auth.GetNonEmptyValueWithBackup(config.HeaderSchema, auth.DefaultHeaderSchema)
	}
}

func WithAuditingConfig(config config.Auditing) ClientOption {
	return func(client *auth.HttpClient) {
		client.Config.Auditing.MetaBy = auth.GetNonEmptyValueWithBackup(config.MetaBy, auth.DefaultMetaBy)
	}
}

func NewHttpClient(AuthServiceBaseUrl string, CurrentServiceName string, options ...ClientOption) *auth.HttpClient {
	client := &auth.HttpClient{
		Config: &config.HttpClientConfig{
			Service: config.Service{
				AuthServiceBaseUrl: AuthServiceBaseUrl,
				CurrentServiceName: CurrentServiceName,
			},
			AccessCode: config.AccessCode{
				Enable:             false,
				SkipUserTokenCheck: true,
				Header:             auth.DefaultHeaderAccessCode,
			},
			RandomKey: config.RandomKey{
				Enable: false,
				Header: auth.DefaultHeaderRandomKey,
			},
			User: config.User{
				Header:       auth.DefaultHeaderUserToken,
				HeaderSchema: auth.DefaultHeaderSchema,
			},
			Client: config.Client{
				EnableIdAndSecret: true,
				Header:            auth.DefaultHeaderClientToken,
				HeaderSchema:      auth.DefaultHeaderSchema,
			},
			Auditing: config.Auditing{
				MetaBy: auth.DefaultMetaBy,
			},
		},
	}
	for _, opt := range options {
		opt(client)
	}
	client.Agent = req.C().SetBaseURL(AuthServiceBaseUrl)
	return client
}
