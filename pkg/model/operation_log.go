package model

import (
	"time"

	"gorm.io/gorm"
)

type PermissionOperationLog struct {
	LogID        string         `gorm:"column:log_id;primaryKey;size:64" json:"log_id"`             //自增id
	OperatorID   string         `gorm:"column:operator_id;not null;size:64" json:"operator_id"`     //用户id
	OperatorName string         `gorm:"column:operator_name;not null;size:32" json:"operator_name"` //用户名
	OperType     string         `gorm:"column:oper_type;not null;size:32" json:"oper_type"`         //操作类型
	OperContent  string         `gorm:"column:oper_content;not null;size:512" json:"oper_content"`  //操作内容
	OperIP       string         `gorm:"column:oper_ip;not null;size:64" json:"oper_ip"`             //操作ip
	OperResult   string         `gorm:"column:oper_result;not null;size:16" json:"oper_result"`     //成功失败
	ErrorMsg     string         `gorm:"column:error_msg;size:512" json:"error_msg"`                 //错误信息
	CreateTime   time.Time      `gorm:"column:create_time;not null;autoCreateTime" json:"create_time"`
	DeletedAt    gorm.DeletedAt `gorm:"column:deleted_at" json:"-"`
}

func (m *PermissionOperationLog) TableName() string {
	return "permission_operation_log"
}
