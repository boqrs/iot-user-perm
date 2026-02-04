package utils

const (
	SuccessCode       = ""
	ParamError        = "PARAM_ERROR"
	DBError           = "DB_ERROR"
	CacheError        = "CACHE_ERROR"
	NotOwnerError     = "NOT_OWNER"
	PermExistError    = "PERM_EXIST"
	PermNotExistError = "PERM_NOT_EXIST"
	DeviceNotFound    = "DEVICE_NOT_FOUND"
	TransactionError  = "TRANSACTION_ERROR"
)

// ErrorMsg 错误信息常量
var ErrorMsg = map[string]string{
	SuccessCode:       "操作成功",
	ParamError:        "参数错误",
	DBError:           "数据库操作失败",
	CacheError:        "缓存操作失败",
	NotOwnerError:     "非设备拥有者，无操作权限",
	PermExistError:    "权限已存在，无需重复操作",
	PermNotExistError: "权限不存在",
	DeviceNotFound:    "设备不存在",
	TransactionError:  "事务操作失败",
}
