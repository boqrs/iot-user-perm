package errs

import "github.com/boqrs/zeus/ginx"

type ErrorCode int

const (
	NoError ErrorCode = iota // 0

	InvalidRequest           ErrorCode = 110000
	Unauthorized             ErrorCode = 110001
	Forbidden                ErrorCode = 110002
	NotFound                 ErrorCode = 110003
	DelayVideoNotFound       ErrorCode = 110004
	Timeout                  ErrorCode = 110005
	Internal                 ErrorCode = 110006
	UnrecognizedDeviceStatus ErrorCode = 110007
	AlreadyBound             ErrorCode = 110008
	NoPermission             ErrorCode = 110009
	NoJobFound               ErrorCode = 110010
	CapabilitiesReach        ErrorCode = 110011
	UploadToOssFailed        ErrorCode = 110012
	LocalJobError            ErrorCode = 110013
	DeviceOfflineError       ErrorCode = 110014
	StatusNotPerm            ErrorCode = 110015
	DeviceJobListLocked      ErrorCode = 110016
	AiTaskAlreadyRunning     ErrorCode = 110017
	AiPointsNotEnough        ErrorCode = 110018
	CopyrightRisk            ErrorCode = 110019
	EM_OK                              = "This operation is successful."
	EM_UNKNOWN                         = "An unknown error occurred."
)

const (
	UnknownError = "Unknown Error"
)

var errorCodeString = map[ErrorCode]string{
	NoError:                  "OK",
	InvalidRequest:           "Invalid Request",                                      //无效的请求,一般指请求格式错误
	Unauthorized:             "Unauthorized",                                         //没有获取到用户信息
	Forbidden:                "Forbidden",                                            //资源操作受到限制
	NotFound:                 "Not Found",                                            //没有找到资源
	Timeout:                  "Timeout",                                              //调用超时
	Internal:                 "Internal Error",                                       //内部业务错误
	DelayVideoNotFound:       "Failed to get video",                                  //延迟视频没有找到
	UnrecognizedDeviceStatus: "Unable to recognize the status of the device",         //无法识别的设备状态
	AlreadyBound:             "device has been bound",                                //设备已经被绑定
	NoPermission:             "User does not have permission to access the resource", //没有权限操作
	NoJobFound:               "No job is available",                                  //打印任务未找到
	CapabilitiesReach:        "Refuse operation, capacity limit has been reached",    //用户使用的资源已经到达限制值
	LocalJobError:            "Local tasks prohibit creating cloud tasks",            //禁止通过本地任务创建云端任务
	DeviceOfflineError:       "The device is offline",                                //设备已经掉线
	StatusNotPerm:            "The current device status does not allow this operation",
	DeviceJobListLocked:      "A job already exists in the job queue",
	AiTaskAlreadyRunning:     "ai task is running or commit, can not cancel",
	AiPointsNotEnough:        "customer points is not enough",
	CopyrightRisk:            "The content you require might be subject to copyright risks",
}

func (code ErrorCode) String() string {
	msg := UnknownError
	if val, ok := errorCodeString[code]; ok {
		msg = val
	}
	return msg
}

func NewError(code ErrorCode) error {
	msg := UnknownError
	if data, ok := errorCodeString[code]; ok {
		msg = data
	}

	return ginx.NewGinError(int(code), msg)
}
