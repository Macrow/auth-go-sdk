package auth

import (
	"github.com/go-logr/logr"
)

type LocalCheck struct {
	config *HttpClientConfig
	logger logr.Logger
}
