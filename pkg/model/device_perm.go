package model

import (
	"time"

	"gorm.io/gorm"
)

// PermissionIotDeviceUser 设备-用户权限绑定表
type PermissionIotDeviceUser struct {
	ID        uint64         `gorm:"primarykey;comment:主键ID"`
	DeviceID  string         `gorm:"size:64;not null;index:idx_device_user;comment:设备ID"`
	UserID    string         `gorm:"size:64;not null;index:idx_device_user;comment:用户ID"`
	PermType  string         `gorm:"size:32;not null;comment:权限类型(OWNER/VIEW/COMMAND)"`
	CreatedAt time.Time      `gorm:"comment:创建时间"`
	UpdatedAt time.Time      `gorm:"comment:更新时间"`
	DeletedAt gorm.DeletedAt `gorm:"index;comment:删除时间"`
}

// TableName 自定义表名
func (p *PermissionIotDeviceUser) TableName() string {
	return "permission_iot_device_user"
}

// PermissionIotDeviceOwner 设备OWNER记录表（冗余，提升查询效率）
type PermissionIotDeviceOwner struct {
	ID          uint64         `gorm:"primarykey;comment:主键ID"`
	DeviceID    string         `gorm:"size:64;not null;unique;comment:设备ID"`
	OwnerUserID string         `gorm:"size:64;not null;comment:设备拥有者用户ID"`
	CreatedAt   time.Time      `gorm:"comment:创建时间"`
	UpdatedAt   time.Time      `gorm:"comment:更新时间"`
	DeletedAt   gorm.DeletedAt `gorm:"index;comment:删除时间"`
}

// TableName 自定义表名
func (p *PermissionIotDeviceOwner) TableName() string {
	return "permission_iot_device_owner"
}
