package model

import (
	"time"

	"gorm.io/gorm"
)

type PermissionIotIdentity struct {
	IdentityCode string         `gorm:"column:identity_code;primaryKey;size:32" json:"identity_code"`
	IdentityName string         `gorm:"column:identity_name;not null;size:32" json:"identity_name"`
	Remark       string         `gorm:"column:remark;size:255" json:"remark"`
	CreateTime   time.Time      `gorm:"column:create_time;not null;autoCreateTime" json:"create_time"`
	UpdateTime   time.Time      `gorm:"column:update_time;not null;autoUpdateTime" json:"update_time"`
	DeletedAt    gorm.DeletedAt `gorm:"column:deleted_at" json:"-"`
}

func (m *PermissionIotIdentity) TableName() string {
	return "permission_iot_identity"
}

type PermissionIotIdentityApi struct {
	ID           uint64         `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	IdentityCode string         `gorm:"column:identity_code;not null;size:32" json:"identity_code"`
	PermID       string         `gorm:"column:perm_id;not null;size:64" json:"perm_id"`
	CreateTime   time.Time      `gorm:"column:create_time;not null;autoCreateTime" json:"create_time"`
	DeletedAt    gorm.DeletedAt `gorm:"column:deleted_at" json:"-"`
}

func (m *PermissionIotIdentityApi) TableName() string {
	return "permission_iot_identity_api"
}
