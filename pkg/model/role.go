package model

import (
	"time"

	"gorm.io/gorm"
)

// PermissionRole 角色模型
type PermissionRole struct {
	RoleCode   string         `gorm:"column:role_code;primaryKey;size:32" json:"role_code"`
	RoleName   string         `gorm:"column:role_name;not null;size:32" json:"role_name"`
	Remark     string         `gorm:"column:remark;size:255" json:"remark"`
	CreateTime time.Time      `gorm:"column:create_time;not null;autoCreateTime" json:"create_time"`
	UpdateTime time.Time      `gorm:"column:update_time;not null;autoUpdateTime" json:"update_time"`
	DeletedAt  gorm.DeletedAt `gorm:"column:deleted_at" json:"-"`
}

func (p *PermissionRole) TableName() string {
	return "permission_role"
}

// PermissionRoleApi 角色-权限绑定模型
type PermissionRoleApi struct {
	ID         uint64         `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	RoleCode   string         `gorm:"column:role_code;not null;size:32" json:"role_code"`
	PermID     string         `gorm:"column:perm_id;not null;size:64" json:"perm_id"`
	CreateTime time.Time      `gorm:"column:create_time;not null;autoCreateTime" json:"create_time"`
	DeletedAt  gorm.DeletedAt `gorm:"column:deleted_at" json:"-"`
}

func (p *PermissionRoleApi) TableName() string {
	return "permission_role_api"
}
