package auth

import "github.com/imroc/req/v3"

type ClientOption func(*Client)

func getNonEmptyValue(val string) string {
	if len(val) == 0 {
		panic("val is empty")
	}
	return val
}

func getNonEmptyValueWithBackup(val string, backup string) string {
	if len(val) > 0 {
		return val
	}
	if len(backup) == 0 {
		panic("backup is empty")
	}
	return backup
}

func WithBasicConfig(config BasicConfig) ClientOption {
	return func(client *Client) {
		baseUrl := getNonEmptyValue(config.AuthServiceBaseUrl)
		client.config.BasicConfig = BasicConfig{
			AuthServiceBaseUrl: baseUrl,
			CurrentServiceName: getNonEmptyValue(config.CurrentServiceName),
			CacheSplitter:      getNonEmptyValueWithBackup(config.CacheSplitter, DefaultCacheSplitter),
		}
		client.agent.SetBaseURL(baseUrl)
	}
}

func WithAccessCodeConfig(config AccessCodeConfig) ClientOption {
	return func(client *Client) {
		client.config.AccessCode = AccessCodeConfig{
			Enable:         config.Enable,
			SkipTokenCheck: config.SkipTokenCheck,
			Header:         getNonEmptyValueWithBackup(config.Header, DefaultHeaderAccessCode),
		}
	}
}

func WithRandomKeyConfig(config RandomKeyConfig) ClientOption {
	return func(client *Client) {
		client.config.RandomKey = RandomKeyConfig{
			Enable: config.Enable,
			Header: getNonEmptyValueWithBackup(config.Header, DefaultHeaderRandomKey),
		}
	}
}

func WithJwtConfig(config JwtConfig) ClientOption {
	return func(client *Client) {
		expireInMinutes := config.ExpireInMinutes
		if expireInMinutes <= 0 {
			expireInMinutes = DefaultJwtExpireInMinutes
		}
		client.config.Jwt = JwtConfig{
			Issuer:          getNonEmptyValueWithBackup(config.Issuer, DefaultIssuer),
			ExpireInMinutes: expireInMinutes,
		}
	}
}

func WithUserConfig(config UserConfig) ClientOption {
	return func(client *Client) {
		client.config.User = UserConfig{
			Header:       getNonEmptyValueWithBackup(config.Header, DefaultHeaderUserToken),
			HeaderSchema: getNonEmptyValueWithBackup(config.HeaderSchema, DefaultHeaderSchema),
		}
	}
}

func WithClientConfig(config ClientConfig) ClientOption {
	return func(client *Client) {
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
	return func(client *Client) {
		client.config.Auditing = AuditingConfig{
			MetaBy: getNonEmptyValueWithBackup(config.MetaBy, DefaultMetaBy),
		}
	}
}

func NewHttpClient(AuthServiceBaseUrl string, CurrentServiceName string, options ...ClientOption) *Client {
	client := &Client{
		config: &HttpClientConfig{
			BasicConfig: BasicConfig{
				AuthServiceBaseUrl: AuthServiceBaseUrl,
				CurrentServiceName: CurrentServiceName,
				CacheSplitter:      DefaultCacheSplitter,
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
			Jwt: JwtConfig{
				Issuer:          DefaultIssuer,
				ExpireInMinutes: DefaultJwtExpireInMinutes,
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
