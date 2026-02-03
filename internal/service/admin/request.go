package admin

import "github.com/boqrs/iot-user-perm/pkg/comm"

type LoginReq struct {
	Username string `json:"username" validate:"required,min=3,max=32"`
	Password string `json:"password" validate:"required"`
	IP       string `json:"ip"`
}

type CreateAdminReq struct {
	Username string `json:"username" validate:"required,min=3,max=32"`
	Password string `json:"password" validate:"required"`
	Remark   string `json:"remark" validate:"max=255"`
}

type UpdatePwdReq struct {
	TargetUserID string `json:"targetUserId,omitempty"`
	OldPassword  string `json:"oldPassword,omitempty"`
	NewPassword  string `json:"newPassword" validate:"required"`
}

type AdminListReq struct {
	Username string `form:"username"`
	Status   string `form:"status"`
	comm.BasePageReq
}

type UpdateApiPermReq struct {
	PermName  string `json:"permName" validate:"required,min=2,max=64"`               // 权限名称
	ApiType   string `json:"apiType" validate:"required,oneof=PERMISSION IOT"`        // API类型
	ApiPath   string `json:"apiPath" validate:"required,max=128"`                     // API路径
	ApiMethod string `json:"apiMethod" validate:"required,oneof=GET POST PUT DELETE"` // API方法
	Remark    string `json:"remark" validate:"max=255"`                               // 备注
	PermId    string `json:"perm_id"`
}

type LogListReq struct {
	OperatorID string `form:"operatorId"`
	OperType   string `form:"operType"`
	StartTime  string `form:"startTime"`
	EndTime    string `form:"endTime"`
	comm.BasePageReq
}

type BindRolePermReq struct {
	RoleCode      string   `json:"roleCode" validate:"required,oneof=SUPER_ADMIN ADMIN"`
	PermissionIds []string `json:"permissionIds" validate:"required,min=1"`
}

type AddApiPermReq struct {
	PermName  string `json:"perm_name" validate:"required,min=2,max=64"`
	ApiType   string `json:"api_type" validate:"required,oneof=PERMISSION IOT"`
	ApiPath   string `json:"api_path" validate:"required,max=128"`
	ApiMethod string `json:"api_method" validate:"required,oneof=GET POST PUT DELETE"`
	Remark    string `json:"remark" validate:"max=255"`
}

type ApiPermListReq struct {
	ApiType  string `form:"apiType"`
	PermName string `form:"permName"`
	comm.BasePageReq
}

type BindIotIdentityPermReq struct {
	IdentityCode  string   `json:"identityCode" validate:"required,oneof=OWNER COMMAND VIEWER"`
	PermissionIds []string `json:"permissionIds" validate:"required,min=1"`
}

type FirstPwdReq struct {
	OldPassword string `json:"oldPassword" validate:"required"` // 原密码
	NewPassword string `json:"newPassword" validate:"required"` // 新密码
	IP          string `json:"ip"`
}
