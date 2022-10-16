package auth

import (
	"github.com/go-logr/logr"
	"github.com/imroc/req/v3"
)

type ClientOption func(*HttpClient)

func WithAccessCodeConfig(config AccessCode) ClientOption {
	return func(client *HttpClient) {
		client.Config.AccessCode.Enable = config.Enable
		client.Config.AccessCode.SkipUserTokenCheck = config.SkipUserTokenCheck
		client.Config.AccessCode.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderAccessCode)
	}
}

func WithRandomKeyConfig(config RandomKey) ClientOption {
	return func(client *HttpClient) {
		client.Config.RandomKey.Enable = config.Enable
		client.Config.RandomKey.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderRandomKey)
	}
}

func WithUserConfig(config User) ClientOption {
	return func(client *HttpClient) {
		client.Config.User.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderUserToken)
		client.Config.User.HeaderSchema = GetNonEmptyValueWithBackup(config.HeaderSchema, DefaultHeaderSchema)
	}
}

func WithClientConfig(config Client) ClientOption {
	return func(client *HttpClient) {
		client.Config.Client.Id = config.Id
		client.Config.Client.Secret = config.Secret
		client.Config.Client.EnableIdAndSecret = config.EnableIdAndSecret
		client.Config.Client.AccessCode = config.AccessCode
		client.Config.Client.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderClientToken)
		client.Config.Client.HeaderSchema = GetNonEmptyValueWithBackup(config.HeaderSchema, DefaultHeaderSchema)
	}
}

func WithAuditingConfig(config Auditing) ClientOption {
	return func(client *HttpClient) {
		client.Config.Auditing.MetaBy = GetNonEmptyValueWithBackup(config.MetaBy, DefaultMetaBy)
	}
}

func WithLogger(logger logr.Logger) ClientOption {
	return func(client *HttpClient) {
		client.logger = logger
	}
}

func NewHttpClient(AuthServiceBaseUrl string, CurrentServiceName string, options ...ClientOption) *HttpClient {
	client := &HttpClient{
		Config: &HttpClientConfig{
			Service: Service{
				AuthServiceBaseUrl: AuthServiceBaseUrl,
				CurrentServiceName: CurrentServiceName,
			},
			AccessCode: AccessCode{
				Enable:             false,
				SkipUserTokenCheck: true,
				Header:             DefaultHeaderAccessCode,
			},
			RandomKey: RandomKey{
				Enable: false,
				Header: DefaultHeaderRandomKey,
			},
			User: User{
				Header:       DefaultHeaderUserToken,
				HeaderSchema: DefaultHeaderSchema,
			},
			Client: Client{
				EnableIdAndSecret: true,
				Header:            DefaultHeaderClientToken,
				HeaderSchema:      DefaultHeaderSchema,
			},
			Auditing: Auditing{
				MetaBy: DefaultMetaBy,
			},
		},
	}
	for _, opt := range options {
		opt(client)
	}
	if client.logger.GetSink() == nil {
		client.logger = logr.Discard()
	}
	client.Agent = req.C().SetBaseURL(AuthServiceBaseUrl)
	return client
}
