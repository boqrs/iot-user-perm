package utils

import (
	"strings"

	pb "github.com/boqrs/iot-user-perm/pkg/proto"
)

// PermTypeEnumToString 枚举转字符串
func PermTypeEnumToString(permType pb.PermissionType) string {
	return permType.String()
}

// StringToPermTypeEnum 字符串转枚举
func StringToPermTypeEnum(permTypeStr string) pb.PermissionType {
	switch permTypeStr {
	case "PERMISSION_TYPE_OWNER":
		return pb.PermissionType_PERMISSION_TYPE_OWNER
	case "PERMISSION_TYPE_VIEW":
		return pb.PermissionType_PERMISSION_TYPE_VIEW
	case "PERMISSION_TYPE_COMMAND":
		return pb.PermissionType_PERMISSION_TYPE_COMMAND
	default:
		return pb.PermissionType_PERMISSION_TYPE_UNKNOWN
	}
}

func PermTypeToString(permType pb.PermissionType) string {
	switch permType {
	case pb.PermissionType_PERMISSION_TYPE_OWNER:
		return "OWNER"
	case pb.PermissionType_PERMISSION_TYPE_COMMAND:
		return "COMMAND"
	case pb.PermissionType_PERMISSION_TYPE_VIEW:
		return "VIEWER"
	default:
		return ""
	}
}

// SplitUserIDs 分割用户ID字符串为切片
func SplitUserIDs(userIDsStr string) []string {
	if userIDsStr == "" {
		return []string{}
	}
	return strings.Split(userIDsStr, ",")
}
