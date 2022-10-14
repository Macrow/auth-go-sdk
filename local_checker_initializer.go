package auth

import (
	"context"
)

type LocalCheckerOption func(checker *LocalAuthChecker)

func WithLocalAccessCodeConfig(config LocalAccessCode) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.Config.LocalAccessCode.Enable = config.Enable
		checker.Config.LocalAccessCode.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderAccessCode)
	}
}

func WithLocalRandomKeyConfig(config LocalRandomKey) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.Config.LocalRandomKey.Enable = config.Enable
		checker.Config.LocalRandomKey.Header = GetNonEmptyValueWithBackup(config.Header, DefaultHeaderRandomKey)
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
	}
}

func WithLocalAuditingConfig(config LocalAuditing) LocalCheckerOption {
	return func(checker *LocalAuthChecker) {
		checker.Config.LocalAuditing.MetaBy = GetNonEmptyValueWithBackup(config.MetaBy, DefaultMetaBy)
	}
}

func NewLocalAuthChecker(ctx context.Context, options ...LocalCheckerOption) *LocalAuthChecker {
	checker := &LocalAuthChecker{
		Ctx: ctx,
		Config: &LocalAuthCheckerConfig{
			LocalAccessCode: LocalAccessCode{
				Enable: false,
				Header: DefaultHeaderAccessCode,
			},
			LocalRandomKey: LocalRandomKey{
				Enable: false,
				Header: DefaultHeaderRandomKey,
			},
			LocalUser: LocalUser{
				Header:       DefaultHeaderUserToken,
				HeaderSchema: DefaultHeaderSchema,
			},
			LocalClient: LocalClient{
				EnableIdAndSecret: true,
				Header:            DefaultHeaderClientToken,
				HeaderSchema:      DefaultHeaderSchema,
			},
			LocalAuditing: LocalAuditing{
				MetaBy: DefaultMetaBy,
			},
		},
	}
	for _, opt := range options {
		opt(checker)
	}
	return checker
}
