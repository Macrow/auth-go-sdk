package auth

type CheckAuthResult struct {
	SkippedAuthCheck bool        `json:"skippedAuthCheck"`
	User             *JwtUser    `json:"user"`
	CustomAuth       interface{} `json:"customAuth"`
}

type CheckPermResult struct {
	SkippedAuthCheck bool        `json:"skippedAuthCheck"`
	User             *JwtUser    `json:"user"`
	CustomAuth       interface{} `json:"customAuth"`
	CustomPerm       interface{} `json:"customPerm"`
}

type CheckClientAuthResult struct {
	ClientAuthOk bool `json:"clientAuthOk"`
}

type CheckClientPermResult struct {
	ClientPermOk bool `json:"clientPermOk"`
}

type Result interface {
	CheckAuthResult | CheckPermResult | CheckClientAuthResult | CheckClientPermResult | any
}

type PagedResult struct {
	Items    []any `json:"items"`
	Total    int   `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"pageSize"`
}

type HttpResult struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Success bool   `json:"success"`
	Result  any    `json:"result"`
}

type HttpResponse[T Result] struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Success bool   `json:"success"`
	Result  *T     `json:"result"`
}
