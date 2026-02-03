package model

import (
	"time"

	"gorm.io/gorm"
)

// PermissionAdmin 权限系统用户模型
type PermissionAdmin struct {
	UserID       string         `gorm:"column:user_id;primaryKey;size:64" json:"user_id"`
	Username     string         `gorm:"column:username;unique;not null;size:32" json:"username"`
	Password     string         `gorm:"column:password;not null;size:128" json:"-"` // 隐藏密码
	RoleCode     string         `gorm:"column:role_code;not null;size:32" json:"role_code"`
	Status       string         `gorm:"column:status;not null;size:16;default:'ENABLED'" json:"status"`
	IsFirstLogin int8           `gorm:"column:is_first_login;not null;default:1" json:"is_first_login"`
	Remark       string         `gorm:"column:remark;size:255" json:"remark"`
	CreateTime   time.Time      `gorm:"column:create_time;not null;autoCreateTime" json:"create_time"`
	UpdateTime   time.Time      `gorm:"column:update_time;not null;autoUpdateTime" json:"update_time"`
	DeletedAt    gorm.DeletedAt `gorm:"column:deleted_at" json:"-"` // 逻辑删除
}

func (p *PermissionAdmin) TableName() string {
	return "permission_admin"
}
