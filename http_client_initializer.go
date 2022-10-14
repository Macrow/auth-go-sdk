package auth

import "github.com/imroc/req/v3"

type ClientOption func(*HttpClient)

func WithBasicConfig(config BasicConfig) ClientOption {
	return func(client *HttpClient) {
		baseUrl := getNonEmptyValue(config.AuthServiceBaseUrl)
		client.config.BasicConfig = BasicConfig{
			AuthServiceBaseUrl: baseUrl,
			CurrentServiceName: getNonEmptyValue(config.CurrentServiceName),
		}
		client.agent.SetBaseURL(baseUrl)
	}
}

func WithAccessCodeConfig(config AccessCodeConfig) ClientOption {
	return func(client *HttpClient) {
		client.config.AccessCode = AccessCodeConfig{
			Enable:         config.Enable,
			SkipTokenCheck: config.SkipTokenCheck,
			Header:         getNonEmptyValueWithBackup(config.Header, DefaultHeaderAccessCode),
		}
	}
}

func WithRandomKeyConfig(config RandomKeyConfig) ClientOption {
	return func(client *HttpClient) {
		client.config.RandomKey = RandomKeyConfig{
			Enable: config.Enable,
			Header: getNonEmptyValueWithBackup(config.Header, DefaultHeaderRandomKey),
		}
	}
}

func WithUserConfig(config UserConfig) ClientOption {
	return func(client *HttpClient) {
		client.config.User = UserConfig{
			Header:       getNonEmptyValueWithBackup(config.Header, DefaultHeaderUserToken),
			HeaderSchema: getNonEmptyValueWithBackup(config.HeaderSchema, DefaultHeaderSchema),
		}
	}
}

func WithClientConfig(config ClientConfig) ClientOption {
	return func(client *HttpClient) {
		client.config.Client = ClientConfig{
			Id:                config.Id,
			Secret:            config.Secret,
			EnableIdAndSecret: config.EnableIdAndSecret,
			AccessCode:        config.AccessCode,
			Header:            getNonEmptyValueWithBackup(config.Header, DefaultHeaderClientToken),
			HeaderSchema:      getNonEmptyValueWithBackup(config.HeaderSchema, DefaultHeaderSchema),
		}
	}
}

func WithAuditingConfig(config AuditingConfig) ClientOption {
	return func(client *HttpClient) {
		client.config.Auditing = AuditingConfig{
			MetaBy: getNonEmptyValueWithBackup(config.MetaBy, DefaultMetaBy),
		}
	}
}

func NewHttpClient(AuthServiceBaseUrl string, CurrentServiceName string, options ...ClientOption) *HttpClient {
	client := &HttpClient{
		config: &HttpClientConfig{
			BasicConfig: BasicConfig{
				AuthServiceBaseUrl: AuthServiceBaseUrl,
				CurrentServiceName: CurrentServiceName,
			},
			AccessCode: AccessCodeConfig{
				Enable:         false,
				SkipTokenCheck: true,
				Header:         DefaultHeaderAccessCode,
			},
			RandomKey: RandomKeyConfig{
				Enable: false,
				Header: DefaultHeaderRandomKey,
			},
			User: UserConfig{
				Header:       DefaultHeaderUserToken,
				HeaderSchema: DefaultHeaderSchema,
			},
			Client: ClientConfig{
				EnableIdAndSecret: true,
				Header:            DefaultHeaderClientToken,
				HeaderSchema:      DefaultHeaderSchema,
			},
			Auditing: AuditingConfig{
				MetaBy: DefaultMetaBy,
			},
		},
	}
	for _, opt := range options {
		opt(client)
	}
	client.agent = req.C().SetBaseURL(AuthServiceBaseUrl)
	return client
}
