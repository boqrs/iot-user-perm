package utils

const (
	SuccessCode       = 0
	ParamError        = 1
	DBError           = 4
	CacheError        = 6
	NotOwnerError     = 2
	PermNotExistError = 3
	DeviceNotFound    = 7
	TransactionError  = 8
)

// ErrorMsg 错误信息常量
var ErrorMsg = map[int]string{
	SuccessCode:       "操作成功",
	ParamError:        "参数错误",
	DBError:           "数据库操作失败",
	CacheError:        "缓存操作失败",
	NotOwnerError:     "非设备拥有者，无操作权限",
	PermNotExistError: "权限不存在",
	DeviceNotFound:    "设备不存在",
	TransactionError:  "事务操作失败",
}
