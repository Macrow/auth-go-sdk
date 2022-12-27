package auth

import "github.com/go-logr/logr"

type LocalCheckerOption func(checker *LocalAuthChecker)

func WithLocalAccessCodeConfig(config LocalAccessCode) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.Config.LocalAccessCode.Enable = config.Enable
		checker.Config.LocalAccessCode.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderAccessCode)
		checker.Config.LocalAccessCode.EncryptContent = config.EncryptContent
	}
}

func WithLocalRandomKeyConfig(config LocalRandomKey) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.Config.LocalRandomKey.Enable = config.Enable
		checker.Config.LocalRandomKey.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderRandomKey)
		checker.Config.LocalRandomKey.EncryptContent = config.EncryptContent
	}
}

func WithLocalUserConfig(config LocalUser) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.Config.LocalUser.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderUserToken)
		checker.Config.LocalUser.HeaderSchema = GetNonEmptyValueWithBackup(config.HeaderSchema, DefaultHeaderSchema)
	}
}

func WithLocalClientConfig(config LocalClient) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.Config.LocalClient.EnableIdAndSecret = config.EnableIdAndSecret
		checker.Config.LocalClient.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderClientToken)
		checker.Config.LocalClient.HeaderSchema = GetNonEmptyValueWithBackup(config.HeaderSchema, DefaultHeaderSchema)
		checker.Config.LocalClient.EncryptContent = config.EncryptContent
	}
}

func WithLocalAuditingConfig(config LocalAuditing) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.Config.LocalAuditing.MetaBy = GetNonEmptyValueWithBackup(config.MetaBy, DefaultMetaBy)
	}
}

func WithAuthCheckerLogger(logger logr.Logger) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.logger = logger
	}
}

func NewLocalAuthChecker(aesKey string, options ...LocalCheckerOption) *LocalAuthChecker {
	checker := &LocalAuthChecker{
		Config: &LocalAuthCheckerConfig{
			LocalAccessCode: LocalAccessCode{
				Enable:         false,
				Header:         DefaultHeaderAccessCode,
				EncryptContent: false,
			},
			LocalRandomKey: LocalRandomKey{
				Enable:         false,
				Header:         DefaultHeaderRandomKey,
				EncryptContent: false,
			},
			LocalUser: LocalUser{
				Header:       DefaultHeaderUserToken,
				HeaderSchema: DefaultHeaderSchema,
			},
			LocalClient: LocalClient{
				EnableIdAndSecret: true,
				Header:            DefaultHeaderClientToken,
				HeaderSchema:      DefaultHeaderSchema,
				EncryptContent:    false,
			},
			LocalAuditing: LocalAuditing{
				MetaBy: DefaultMetaBy,
			},
		},
		AesUtil: NewAesUtil(aesKey),
	}
	for _, opt := range options {
		opt(checker)
	}
	if checker.logger.GetSink() == nil {
		checker.logger = logr.Discard()
	}
	return checker
}
