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

// StringToPermType 将字符串（OWNER/COMMAND/VIEWER）转换为gRPC枚举
func StringToPermType(permStr string) pb.PermissionType {
	switch permStr {
	case "OWNER":
		return pb.PermissionType_PERMISSION_TYPE_OWNER
	case "COMMAND":
		return pb.PermissionType_PERMISSION_TYPE_COMMAND
	case "VIEWER":
		return pb.PermissionType_PERMISSION_TYPE_VIEW
	default:
		return pb.PermissionType_PERMISSION_TYPE_UNKNOWN
	}
}

// PermTypesToStrings 将gRPC枚举列表转换为字符串列表
func PermTypesToStrings(permTypes []pb.PermissionType) []string {
	strs := make([]string, 0, len(permTypes))
	for _, pt := range permTypes {
		str := PermTypeToString(pt)
		if str != "" {
			strs = append(strs, str)
		}
	}
	return strs
}
