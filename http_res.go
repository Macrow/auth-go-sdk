package auth

type CheckAuthResult struct {
	SkippedAuthCheck bool        `json:"skippedAuthCheck,omitempty"`
	User             *JwtUser    `json:"user,omitempty"`
	CustomAuth       interface{} `json:"customAuth,omitempty"`
}

type CheckPermResult struct {
	SkippedAuthCheck bool        `json:"skippedAuthCheck,omitempty"`
	User             *JwtUser    `json:"user,omitempty"`
	CustomAuth       interface{} `json:"customAuth,omitempty"`
	CustomPerm       interface{} `json:"customPerm,omitempty"`
}

type CheckClientAuthResult struct {
	ClientAuthOk bool `json:"clientAuthOk,omitempty"`
}

type CheckClientPermResult struct {
	ClientPermOk bool `json:"clientPermOk,omitempty"`
}

type Result interface {
	CheckAuthResult | CheckPermResult | CheckClientAuthResult | CheckClientPermResult | any
}

type PagedResult struct {
	Items    []any `json:"items,omitempty"`
	Total    int   `json:"total,omitempty"`
	Page     int   `json:"page,omitempty"`
	PageSize int   `json:"pageSize,omitempty"`
}

type HttpResult struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
	Result  any    `json:"result,omitempty"`
}

type HttpResponse[T Result] struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
	Result  *T     `json:"result,omitempty"`
}
