package admin

import (
	"github.com/boqrs/iot-user-perm/pkg/comm"
	"github.com/boqrs/iot-user-perm/pkg/model"
)

type AdminLoginResp struct {
	Token        string `json:"token"`
	UserId       string `json:"user_id"`
	Username     string `json:"username"`
	RoleCode     string `json:"role_code"`
	IsFirstLogin bool   `json:"is_first_login"`
}

type CreateAdminResp struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Status   string `json:"status"`
}

type AdminListResp struct {
	Detail []model.PermissionAdmin `json:"detail"`
	comm.PageBaseResp
}

type LogListResp struct {
	Detail []model.PermissionOperationLog `json:"detail"`
	comm.PageBaseResp
}

type RolePermResp struct {
	RoleCode string                    `json:"role_code"`
	RoleName string                    `json:"role_name"`
	PermList []model.PermissionRoleApi `json:"perm_list"`
}

type AddApiPermResp struct {
	PermID   string `json:"perm_id"`
	PermName string `json:"perm_name"`
}

type ApiPermListResp struct {
	Detail []model.PermissionApi `json:"detail"`
	comm.PageBaseResp
}
