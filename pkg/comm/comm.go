package comm

const (
	EnvPro           = "pro"
	EnvDev           = "dev"
	EnvTest          = "test"
	RequestUserIpKey = "UserIp"
)

type BasePageReq struct {
	CurrentPage int `form:"currentPage" json:"currentPage"`
	PageSize    int `form:"pageSize" json:"pageSize"`
}

type PageBaseResp struct {
	Total int64 `json:"total"`
	Next  bool  `json:"next"`
}
