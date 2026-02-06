package service

import (
	"context"

	"github.com/boqrs/iot-user-perm/pkg/model"
	pb "github.com/boqrs/iot-user-perm/pkg/proto"
)

const (
	// 内置角色
	RoleCodeSuperAdmin = "SUPER_ADMIN"
	// 内置API权限
	PermIDAll = "perm_all"
)

type DeviceVO struct {
	DeviceId     string `json:"device_id"`
	Model        string `json:"model"`
	Firmware     string `json:"firmware"`
	OnlineStatus string `json:"online_status"`
	PermType     string `json:"perm_type"`
}

type UserDeviceItem struct {
	DeviceID string `gorm:"column:device_id" json:"device_id"`
	PermType string `gorm:"column:perm_type" json:"perm_type"`
}

type DevicePermUserItem struct {
	UserID   string `gorm:"column:user_id" json:"user_id"`
	PermType string `gorm:"column:perm_type" json:"perm_type"`
}

// ========== 辅助函数：判断权限类型是否在筛选列表中 ==========
func containsPermType(filter []pb.DevicePermType, target pb.DevicePermType) bool {
	for _, pt := range filter {
		if pt == target {
			return true
		}
	}
	return false
}

// ========== 辅助函数 ==========
// containsString 检查字符串是否在列表中
func containsString(list []string, str string) bool {
	for _, s := range list {
		if s == str {
			return true
		}
	}
	return false
}

func getRequestID(ctx context.Context) string {
	if rid, ok := ctx.Value("request_id").(string); ok {
		return rid
	}
	return "unknown"
}

func joinSlice(slice []string, sep string) string {
	var res string
	for i, v := range slice {
		if i == 0 {
			res = v
		} else {
			res += sep + v
		}
	}
	return res
}

// IsBuiltInApiPerm 检查是否为系统内置API权限（禁止删除）
func IsBuiltInApiPerm(permID string) bool {
	return permID == PermIDAll
}

func ParsePageParam(page *pb.PageRequest) (int32, int32) {
	_page := int32(1)
	_size := int32(10)
	if page != nil {
		if page.Page > 0 {
			_page = page.Page
		}
		if page.Size > 0 {
			_size = page.Size
		}
	}
	// 限制最大页大小，避免全表查询
	if _size > 50 {
		_size = 50
	}
	return _page, _size
}

func ApiPermModelsToProtos(ms []*model.PermissionApi) []*pb.ApiPermInfo {
	var list []*pb.ApiPermInfo
	for _, m := range ms {
		list = append(list, ApiPermModelToProto(m))
	}
	return list
}

func ApiPermModelToProto(m *model.PermissionApi) *pb.ApiPermInfo {
	if m == nil {
		return nil
	}
	return &pb.ApiPermInfo{
		PermId:    m.PermID,
		PermName:  m.PermName,
		ApiPath:   m.ApiPath,
		ApiMethod: pb.HttpMethod(pb.HttpMethod_value[m.ApiMethod]),
		Remark:    m.Remark,
	}
}

func IsBuiltInRole(roleCode string) bool {
	return roleCode == RoleCodeSuperAdmin
}

// 以下为通用解析辅助方法（可根据Proto生成的结构体做类型断言，精准解析）
func getOperatorID(req interface{}) string {
	// 示例：对BindDeviceRequest做类型断言
	if r, ok := req.(*pb.BindDeviceRequest); ok {
		return r.OperatorUserId
	}
	if r, ok := req.(*pb.AuthorizeDevicePermissionRequest); ok {
		return r.OperatorUserId
	}
	// 其他接口依次添加...
	return "unknown-operator"
}
func getOperatorName(req interface{}) string {
	if r, ok := req.(*pb.BindDeviceRequest); ok {
		return r.OperatorName
	}
	// 其他接口依次添加...
	return "未知操作人"
}
func getOperType(req interface{}) pb.OperType {
	if _, ok := req.(*pb.BindDeviceRequest); ok {
		return pb.OperType_OPER_TYPE_BIND_DEVICE
	}
	if _, ok := req.(*pb.AuthorizeDevicePermissionRequest); ok {
		return pb.OperType_OPER_TYPE_AUTHORIZE_DEVICE
	}
	if _, ok := req.(*pb.AddApiPermRequest); ok {
		return pb.OperType_OPER_TYPE_ADD_API
	}
	if _, ok := req.(*pb.AddRoleRequest); ok {
		return pb.OperType_OPER_TYPE_ADD_ROLE
	}
	if _, ok := req.(*pb.BindRoleApiRequest); ok {
		return pb.OperType_OPER_TYPE_BIND_ROLE_API
	}
	return pb.OperType_OPER_TYPE_UNKNOWN
}
func getOperIP(req interface{}) string {
	if r, ok := req.(*pb.BindDeviceRequest); ok {
		return r.OperIp
	}
	if r, ok := req.(*pb.AuthorizeDevicePermissionRequest); ok {
		return r.OperIp
	}
	// 其他接口依次添加...
	return "unknown-ip"
}
