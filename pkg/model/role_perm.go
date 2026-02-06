package model

import (
	"time"

	"gorm.io/gorm"
)

// PermissionApi API权限模型（对应permission_api表）
// 核心作用：定义系统中所有可被权限管控的API接口，关联角色/IOT身份
type PermissionApi struct {
	// ---------- 核心业务字段 ----------
	PermID    string `gorm:"column:perm_id;primaryKey;size:64;comment:权限ID" json:"perm_id"`                          // 主键，格式：perm_xxx（如perm_10001）
	PermName  string `gorm:"column:perm_name;not null;size:64;comment:权限名称" json:"perm_name"`                        // 如："IOT设备控制"
	ApiPath   string `gorm:"column:api_path;not null;size:128;comment:API路径" json:"api_path"`                        // 如："/api/iot/device/control"
	ApiMethod string `gorm:"column:api_method;not null;size:16;comment:API方法：GET/POST/PUT/DELETE" json:"api_method"` // HTTP方法

	// ---------- 扩展字段 ----------
	Remark string `gorm:"column:remark;size:255;default:'';comment:备注" json:"remark"` // 权限说明

	// ---------- 通用审计字段 ----------
	CreateTime time.Time      `gorm:"column:create_time;not null;autoCreateTime;comment:创建时间" json:"create_time"` // GORM自动填充创建时间
	UpdateTime time.Time      `gorm:"column:update_time;not null;autoUpdateTime;comment:更新时间" json:"update_time"` // GORM自动填充更新时间
	DeletedAt  gorm.DeletedAt `gorm:"column:deleted_at;comment:逻辑删除时间" json:"-"`                                  // 逻辑删除字段（接口返回隐藏）
}

// TableName 指定模型对应的数据库表名（避免GORM自动复数化）
func (p *PermissionApi) TableName() string {
	return "permission_api"
}

// 1. PermissionIotDeviceUser 补充复合索引（适配「按用户+权限类型查设备」的高频场景）
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

// 2. PermissionRoleApi 补充复合索引（适配「按角色查所有API权限」的高频场景）
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
