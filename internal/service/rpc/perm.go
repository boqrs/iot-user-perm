package rpc

import (
	"context"
	"fmt"

	"github.com/boqrs/comm/database/cache"
	"github.com/boqrs/iot-user-perm/config"
	pb "github.com/boqrs/iot-user-perm/pkg/proto"
	"github.com/boqrs/iot-user-perm/pkg/utils"
	"github.com/boqrs/zeus/log"
	logger "github.com/boqrs/zeus/log"
	"gorm.io/gorm"
)

type Service interface {
	BindDevice(ctx context.Context, req *pb.BindDeviceRequest) (*pb.BaseResponse, error)
	UnbindDevice(ctx context.Context, req *pb.UnbindDeviceRequest) (*pb.BaseResponse, error)
	AuthorizeDevicePermission(ctx context.Context, req *pb.AuthorizeDevicePermissionRequest) (*pb.BaseResponse, error)
	RevokeDevicePermission(ctx context.Context, req *pb.RevokeDevicePermissionRequest) (*pb.BaseResponse, error)
	GetDevicePermission(ctx context.Context, req *pb.GetDevicePermissionRequest) (*pb.GetDevicePermissionResponse, error)
	GetDevicePermissionUsers(ctx context.Context, req *pb.GetDevicePermissionUsersRequest) (*pb.GetDevicePermissionUsersResponse, error)
	BatchDeleteDevicePermission(ctx context.Context, req *pb.BatchDeleteDevicePermissionRequest) (*pb.BaseResponse, error)
	BatchGetDevicePerms(ctx context.Context, req *pb.BatchGetDevicePermsRequest) (*pb.BatchGetDevicePermsResponse, error)
	BatchGetUserDevices(ctx context.Context, req *pb.BatchGetUserDevicesRequest) (*pb.BatchGetUserDevicesResponse, error)
}

type service struct {
	dao *daoService
	log log.Logger
}

func NewService(sql *gorm.DB, cfg *config.Config, ch cache.Cache, l logger.Logger) Service {
	return &service{
		dao: newdaoService(sql, cfg, ch, l),
		log: l.WithField("rpc", "service"),
	}
}

// ========== 1. 绑定设备（成为OWNER） ==========
func (s *service) BindDevice(ctx context.Context, req *pb.BindDeviceRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.UserId == "" || req.DeviceId == "" {
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.ParamError,
			ErrorMsg:  "User ID or Device ID is missing",
		}, nil
	}

	// 3. 数据库操作
	if err := s.dao.CreateDeviceOwner(req.DeviceId, req.UserId); err != nil {
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.DBError,
			ErrorMsg:  err.Error(),
		}, nil
	}

	// 5. 更新缓存（永久有效）
	// 5.1 设置单用户-设备权限缓存
	_ = s.dao.SetUserDevicePermCache(req.UserId, req.DeviceId, "PERMISSION_TYPE_OWNER")
	// 5.2 设置设备OWNER缓存
	_ = s.dao.SetDeviceOwnerCache(req.DeviceId, req.UserId)
	// 5.3 添加用户设备列表缓存
	_ = s.dao.SAddUserDevicesCache(req.UserId, req.DeviceId)
	// 5.4 更新设备权限用户缓存
	permUsers := map[string][]string{
		"PERMISSION_TYPE_OWNER": {req.UserId},
	}
	_ = s.dao.UpdateDevicePermUsersCache(req.DeviceId, permUsers)

	// 6. 返回成功响应
	return &pb.BaseResponse{
		Success:   true,
		ErrorCode: utils.SuccessCode,
		ErrorMsg:  utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 2. 解绑设备（删除OWNER权限） ==========
func (s *service) UnbindDevice(ctx context.Context, req *pb.UnbindDeviceRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.UserId == "" || req.DeviceId == "" {
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.ParamError,
			ErrorMsg:  "User ID or Device ID is missing",
		}, nil
	}

	// 3. 数据库操作
	if err := s.dao.DeleteDeviceOwner(req.DeviceId, req.UserId); err != nil {
		s.log.Errorf("Failed to delete device OWNER: %v", err)
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.DBError,
			ErrorMsg:  err.Error(),
		}, nil
	}

	// 5. 删除缓存
	// 5.1 删除单用户-设备权限缓存
	_ = s.dao.DelUserDevicePermCache(req.UserId, req.DeviceId)
	// 5.2 删除设备OWNER缓存
	_ = s.dao.DelDeviceOwnerCache(req.DeviceId)
	// 5.3 移除用户设备列表缓存
	_ = s.dao.SRemUserDevicesCache(req.UserId, req.DeviceId)
	_ = s.dao.DelEmptyUserDevicesCache(req.UserId)
	// 5.4 获取该设备的授权用户，批量删除其缓存
	authorizedUsers, _ := s.dao.GetAuthorizedUsers(req.DeviceId)
	for _, uId := range authorizedUsers {
		_ = s.dao.DelUserDevicePermCache(uId, req.DeviceId)
		_ = s.dao.SRemUserDevicesCache(uId, req.DeviceId)
		_ = s.dao.DelEmptyUserDevicesCache(uId)
	}
	// 5.5 删除设备权限用户缓存
	if err := s.dao.BatchDelDevicePermCache(req.DeviceId); err != nil {
		s.log.Errorf("failed to batch delete device perm cache, error: %s", err.Error())
	}

	// 6. 返回成功响应
	return &pb.BaseResponse{
		Success:   true,
		ErrorCode: utils.SuccessCode,
		ErrorMsg:  utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 3. 授权其他用户设备权限 ==========
func (s *service) AuthorizeDevicePermission(ctx context.Context, req *pb.AuthorizeDevicePermissionRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.OwnerUserId == "" || req.AuthorizedUserId == "" || req.DeviceId == "" || req.PermType == pb.PermissionType_PERMISSION_TYPE_UNKNOWN {
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.ParamError,
			ErrorMsg:  "The Authorizer ID, Grantee ID, Device ID, and Permission Type are required",
		}, nil
	}
	// 校验权限类型（仅VIEW/COMMAND）
	if req.PermType != pb.PermissionType_PERMISSION_TYPE_VIEW && req.PermType != pb.PermissionType_PERMISSION_TYPE_COMMAND {
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.ParamError,
			ErrorMsg:  "Only VIEW/COMMAND type permissions are supported for authorization",
		}, nil
	}
	// 校验授权方和被授权方不能是同一人
	if req.OwnerUserId == req.AuthorizedUserId {
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.ParamError,
			ErrorMsg:  "The Authorizer and Grantee cannot be the same user",
		}, nil
	}

	// 3. 转换枚举为字符串
	permTypeStr := utils.PermTypeEnumToString(req.PermType)

	// 4. 数据库操作
	if err := s.dao.CreateAuthorizedPerm(req.OwnerUserId, req.AuthorizedUserId, req.DeviceId, permTypeStr); err != nil {
		s.log.Errorf("Failed to create the authorization permission: %v", err)
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.DBError,
			ErrorMsg:  err.Error(),
		}, nil
	}

	// 6. 更新缓存
	// 6.1 设置被授权方单设备权限缓存
	_ = s.dao.SetUserDevicePermCache(req.AuthorizedUserId, req.DeviceId, permTypeStr)
	// 6.2 添加被授权方设备列表缓存
	_ = s.dao.SAddUserDevicesCache(req.AuthorizedUserId, req.DeviceId)
	// 6.3 更新设备权限用户缓存
	permUsers, _ := s.dao.GetDeviceAllPermUsers(req.DeviceId)
	_ = s.dao.UpdateDevicePermUsersCache(req.DeviceId, permUsers)

	// 7. 返回成功响应
	return &pb.BaseResponse{
		Success:   true,
		ErrorCode: utils.SuccessCode,
		ErrorMsg:  utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 4. 撤销其他用户设备权限 ==========
func (s *service) RevokeDevicePermission(ctx context.Context, req *pb.RevokeDevicePermissionRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.OwnerUserId == "" || req.AuthorizedUserId == "" || req.DeviceId == "" || req.PermType == pb.PermissionType_PERMISSION_TYPE_UNKNOWN {
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.ParamError,
			ErrorMsg:  "The Authorizer ID, Grantee ID, Device ID, and Permission Type cannot be empty",
		}, nil
	}

	// 3. 转换枚举为字符串
	permTypeStr := utils.PermTypeEnumToString(req.PermType)

	// 4. 数据库操作
	if err := s.dao.DeleteAuthorizedPerm(req.OwnerUserId, req.AuthorizedUserId, req.DeviceId, permTypeStr); err != nil {
		s.log.Errorf("Failed to delete the authorization permission: %v", err)
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.DBError,
			ErrorMsg:  err.Error(),
		}, nil
	}

	// 6. 删除缓存
	// 6.1 删除被授权方单设备权限缓存
	_ = s.dao.DelUserDevicePermCache(req.AuthorizedUserId, req.DeviceId)
	// 6.2 移除被授权方设备列表缓存
	_ = s.dao.SRemUserDevicesCache(req.AuthorizedUserId, req.DeviceId)
	_ = s.dao.DelEmptyUserDevicesCache(req.AuthorizedUserId)
	// 6.3 更新设备权限用户缓存
	permUsers, _ := s.dao.GetDeviceAllPermUsers(req.DeviceId)
	_ = s.dao.UpdateDevicePermUsersCache(req.DeviceId, permUsers)

	// 7. 返回成功响应
	return &pb.BaseResponse{
		Success:   true,
		ErrorCode: utils.SuccessCode,
		ErrorMsg:  utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 5. 查询用户设备权限 ==========
func (s *service) GetDevicePermission(ctx context.Context, req *pb.GetDevicePermissionRequest) (*pb.GetDevicePermissionResponse, error) {
	// 1. 参数校验
	if req.UserId == "" || req.DeviceId == "" {
		return &pb.GetDevicePermissionResponse{
			BaseResp: &pb.BaseResponse{
				Success:   false,
				ErrorCode: utils.ParamError,
				ErrorMsg:  "The Authorizer ID, Grantee ID, Device ID, and Permission Type are required",
			},
			PermType: pb.PermissionType_PERMISSION_TYPE_UNKNOWN,
		}, nil
	}

	// 2. 查缓存
	permTypeStr, err := s.dao.GetUserDevicePerm(req.UserId, req.DeviceId)
	if err == nil {
		// 刷新缓存为永久有效
		key := fmt.Sprintf(KeyUserDevicePerm, req.UserId, req.DeviceId)
		_ = s.dao.RefreshPermCache(key)
		// 转换字符串为枚举
		permType := utils.StringToPermTypeEnum(permTypeStr)
		return &pb.GetDevicePermissionResponse{
			BaseResp: &pb.BaseResponse{
				Success:   true,
				ErrorCode: utils.SuccessCode,
				ErrorMsg:  utils.ErrorMsg[utils.SuccessCode],
			},
			PermType: permType,
		}, nil
	}

	// 3. 缓存未命中，查数据库
	permTypeStr, err = s.dao.GetUserDevicePerm(req.UserId, req.DeviceId)
	if err != nil {
		s.log.Errorf("Failed to query user device permissions: %v", err)
		return &pb.GetDevicePermissionResponse{
			BaseResp: &pb.BaseResponse{
				Success:   false,
				ErrorCode: utils.DBError,
				ErrorMsg:  fmt.Sprintf("Failed to query user device permissions: %v", err),
			},
			PermType: pb.PermissionType_PERMISSION_TYPE_UNKNOWN,
		}, nil
	}

	// 4. 回写缓存（永久有效）
	_ = s.dao.SetUserDevicePermCache(req.UserId, req.DeviceId, permTypeStr)

	// 5. 转换字符串为枚举
	permType := utils.StringToPermTypeEnum(permTypeStr)

	// 6. 返回响应
	return &pb.GetDevicePermissionResponse{
		BaseResp: &pb.BaseResponse{
			Success:   true,
			ErrorCode: utils.SuccessCode,
			ErrorMsg:  utils.ErrorMsg[utils.SuccessCode],
		},
		PermType: permType,
	}, nil
}

// ========== 6. 批量删除设备所有权限 ==========
func (s *service) BatchDeleteDevicePermission(ctx context.Context, req *pb.BatchDeleteDevicePermissionRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.DeviceId == "" {
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.ParamError,
			ErrorMsg:  "Device ID cannot be empty",
		}, nil
	}

	// 3. 数据库操作
	if err := s.dao.BatchDeleteDevicePerm(req.DeviceId); err != nil {
		s.log.Errorf("Batch deletion of device permissions failed: %v", err)
		return &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.DBError,
			ErrorMsg:  err.Error(),
		}, nil
	}

	// 5. 批量删除缓存
	_ = s.dao.BatchDelDevicePermCache(req.DeviceId)

	// 6. 返回成功响应
	return &pb.BaseResponse{
		Success:   true,
		ErrorCode: utils.SuccessCode,
		ErrorMsg:  utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 7. 查询设备的所有权限用户列表 ==========
func (s *service) GetDevicePermissionUsers(ctx context.Context, req *pb.GetDevicePermissionUsersRequest) (*pb.GetDevicePermissionUsersResponse, error) {
	resp := &pb.GetDevicePermissionUsersResponse{
		BaseResp: &pb.BaseResponse{
			Success:   true,
			ErrorCode: utils.SuccessCode,
			ErrorMsg:  utils.ErrorMsg[utils.SuccessCode],
		},
	}

	// 1. 参数校验
	if req.DeviceId == "" {
		resp.BaseResp = &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.ParamError,
			ErrorMsg:  "设备ID不能为空",
		}
		return resp, nil
	}

	// 2. 判断是否需要返回所有用户
	if req.NeedAll {
		// 2.1 查缓存Set
		userIDs, err := s.dao.GetDevicePermUsersSetCache(req.DeviceId)
		if err == nil && len(userIDs) > 0 {
			// 刷新缓存为永久有效
			key := fmt.Sprintf(KeyDevicePermUsersSet, req.DeviceId)
			_ = s.dao.RefreshPermCache(key)
			resp.AllUserIds = userIDs
			return resp, nil
		}

		// 2.2 缓存未命中，查数据库
		permUsers, err := s.dao.GetDeviceAllPermUsers(req.DeviceId)
		if err != nil {
			s.log.Errorf("Failed to query all users with permissions on the device: %v", err)
			resp.BaseResp = &pb.BaseResponse{
				Success:   false,
				ErrorCode: utils.DBError,
				ErrorMsg:  fmt.Sprintf("查询设备所有权限用户失败: %v", err),
			}
			return resp, nil
		}

		// 2.3 组装全量用户列表
		allUserIDs := make([]string, 0)
		for _, userIDs := range permUsers {
			allUserIDs = append(allUserIDs, userIDs...)
		}
		resp.AllUserIds = allUserIDs

		// 2.4 异步回写缓存
		go func() {
			_ = s.dao.UpdateDevicePermUsersCache(req.DeviceId, permUsers)
		}()

		return resp, nil
	}

	// 3. 按类型分类返回
	// 3.1 查缓存Hash

	permUserHash, err := s.dao.GetDevicePermUsersHashCache(req.DeviceId)
	if err == nil && len(permUserHash) > 0 {
		// 刷新缓存为永久有效
		key := fmt.Sprintf(KeyDevicePermUsersHash, req.DeviceId)
		_ = s.dao.RefreshPermCache(key)

		// 3.2 组装perm_user_map
		permUserMap := make(map[string]*pb.PermUserList)
		for permTypeStr, userIDsStr := range permUserHash {
			// 过滤筛选的权限类型
			permType := utils.StringToPermTypeEnum(permTypeStr)
			if len(req.FilterPermTypes) > 0 && !containsPermType(req.FilterPermTypes, permType) {
				continue
			}
			// 分割用户ID
			userIDs := utils.SplitUserIDs(userIDsStr)
			permUserMap[utils.PermTypeEnumToString(permType)] = &pb.PermUserList{
				UserIds: userIDs,
			}
		}

		resp.PermUserMap = permUserMap

		// 3.3 组装完整用户列表
		userList := make([]*pb.DevicePermissionUser, 0)
		for permTypeStr, userIDsStr := range permUserHash {
			permType := utils.StringToPermTypeEnum(permTypeStr)
			userIDs := utils.SplitUserIDs(userIDsStr)
			for _, userID := range userIDs {
				userList = append(userList, &pb.DevicePermissionUser{
					UserId:   userID,
					PermType: permType,
				})
			}
		}
		resp.UserList = userList

		return resp, nil
	}

	// 3.4 缓存未命中，查数据库
	permUsers, err := s.dao.GetDeviceAllPermUsers(req.DeviceId)
	if err != nil {
		s.log.Errorf("查询设备所有权限用户失败: %v", err)
		resp.BaseResp = &pb.BaseResponse{
			Success:   false,
			ErrorCode: utils.DBError,
			ErrorMsg:  fmt.Sprintf("查询设备所有权限用户失败: %v", err),
		}
		return resp, nil
	}

	// 3.5 组装perm_user_map
	permUserMap := make(map[string]*pb.PermUserList)
	userList := make([]*pb.DevicePermissionUser, 0)
	for permTypeStr, userIDs := range permUsers {
		permType := utils.StringToPermTypeEnum(permTypeStr)
		// 过滤筛选的权限类型
		if len(req.FilterPermTypes) > 0 && !containsPermType(req.FilterPermTypes, permType) {
			continue
		}
		// 组装perm_user_map
		permUserMap[utils.PermTypeEnumToString(permType)] = &pb.PermUserList{
			UserIds: userIDs,
		}
		// 组装完整用户列表
		for _, userID := range userIDs {
			userList = append(userList, &pb.DevicePermissionUser{
				UserId:   userID,
				PermType: permType,
			})
		}
	}
	resp.PermUserMap = permUserMap
	resp.UserList = userList

	// 3.6 异步回写缓存
	go func() {
		_ = s.dao.UpdateDevicePermUsersCache(req.DeviceId, permUsers)
	}()

	return resp, nil
}

// ========== 8. 查询设备的所有权限用户列表 ==========
func (s *service) BatchGetUserDevices(ctx context.Context, req *pb.BatchGetUserDevicesRequest) (*pb.BatchGetUserDevicesResponse, error) {
	resp := &pb.BatchGetUserDevicesResponse{
		BaseResp: &pb.BaseResponse{
			Success:   true,
			ErrorCode: "0",
			ErrorMsg:  "",
		},
	}

	// 1. 参数校验
	if req.UserId == "" {
		resp.BaseResp = &pb.BaseResponse{
			Success:   false,
			ErrorCode: "1", // 参数错误
			ErrorMsg:  "user_id should not be empty",
		}
		return resp, nil
	}
	// 分页参数默认值
	page := req.Page
	if page <= 0 {
		page = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 || pageSize > 100 { // 限制最大页大小，防止查询过多数据
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	filterPermStrs := utils.PermTypesToStrings(req.FilterPermTypes)

	// 3. 优先查缓存（用户设备列表）
	deviceIDs, err := s.dao.SMembersUserDevicesCache(req.UserId)
	if err != nil {
		s.log.Warn("Failed to query user device cache", "user_id", req.UserId, "error", err)
	} else if len(deviceIDs) > 0 {
		// 缓存命中：刷新缓存过期时间
		cacheKey := fmt.Sprintf(KeyUserDevices, req.UserId)
		_ = s.dao.RefreshCache(cacheKey)

		// 3.1 批量查询这些设备的权限类型（筛选+分页）
		deviceList := make([]*pb.UserDeviceItem, 0, len(deviceIDs))
		for _, deviceID := range deviceIDs {
			// 查询单个设备权限
			permStr, err := s.dao.GetUserDevicePerm(req.UserId, deviceID)
			if err != nil {
				s.log.Warn("Failed to query user device permissions", "user_id", req.UserId, "device_id", deviceID, "error", err)
				continue
			}
			permType := utils.StringToPermType(permStr)

			// 筛选权限类型
			if len(filterPermStrs) > 0 && !containsString(filterPermStrs, permStr) {
				continue
			}

			deviceList = append(deviceList, &pb.UserDeviceItem{
				DeviceId: deviceID,
				PermType: permType,
			})
		}

		// 3.2 分页处理
		total := int64(len(deviceList))
		end := offset + pageSize
		if end > int32(total) {
			end = int32(total)
		}
		if offset < int32(total) {
			resp.DeviceList = deviceList[offset:end]
		}
		resp.Total = total
		return resp, nil
	}

	// 4. 缓存未命中：查数据库
	items, total, err := s.dao.GetUserDeviceList(req.UserId, filterPermStrs, int(offset), int(pageSize))
	if err != nil {
		s.log.Error("failed to find user list", "user_id", req.UserId, "error", err)
		resp.BaseResp = &pb.BaseResponse{
			Success:   false,
			ErrorCode: "2", // 数据库错误
			ErrorMsg:  fmt.Sprintf("query failed: %v", err),
		}
		return resp, nil
	}

	// 5. 组装响应
	deviceList := make([]*pb.UserDeviceItem, 0, len(items))
	deviceIDSet := make([]string, 0, len(items)) // 用于缓存
	for _, item := range items {
		permType := utils.StringToPermType(item.PermType)
		deviceList = append(deviceList, &pb.UserDeviceItem{
			DeviceId: item.DeviceID,
			PermType: permType,
		})
		deviceIDSet = append(deviceIDSet, item.DeviceID)
	}
	resp.DeviceList = deviceList
	resp.Total = total

	// 6. 异步回写缓存（非阻塞，不影响响应）
	go func() {
		if err := s.dao.SAddUserDevicesCache(req.UserId, deviceIDSet...); err != nil {
			s.log.Warn("Failed to write back user device cache", "user_id", req.UserId, "error", err)
		}
	}()

	return resp, nil

}

func (s *service) BatchGetDevicePerms(ctx context.Context, req *pb.BatchGetDevicePermsRequest) (*pb.BatchGetDevicePermsResponse, error) {
	// 初始化响应
	resp := &pb.BatchGetDevicePermsResponse{
		BaseResp: &pb.BaseResponse{
			Success:   true,
			ErrorCode: "0",
			ErrorMsg:  "",
		},
	}

	// 1. 参数校验
	if len(req.DeviceIds) == 0 {
		resp.BaseResp = &pb.BaseResponse{
			Success:   false,
			ErrorCode: "1", // 参数错误
			ErrorMsg:  "device_ids should not be empty",
		}
		return resp, nil
	}
	if len(req.DeviceIds) > 100 { // 限制批量查询数量，防止性能问题
		resp.BaseResp = &pb.BaseResponse{
			Success:   false,
			ErrorCode: "1",
			ErrorMsg:  "device_ids must be lower than 100",
		}
		return resp, nil
	}

	// 2. 批量查询数据库
	devicePermMap, err := s.dao.BatchGetDevicePerms(req.DeviceIds, req.UserId)
	if err != nil {
		s.log.Error("批量查询设备权限失败", "device_ids", req.DeviceIds, "user_id", req.UserId, "error", err)
		resp.BaseResp = &pb.BaseResponse{
			Success:   false,
			ErrorCode: "2", // 数据库错误
			ErrorMsg:  fmt.Sprintf("查询失败: %v", err),
		}
		return resp, nil
	}

	// 3. 组装响应
	devicePermList := make([]*pb.DevicePermItem, 0, len(req.DeviceIds))
	for _, deviceID := range req.DeviceIds {
		item := &pb.DevicePermItem{DeviceId: deviceID}
		permItems, ok := devicePermMap[deviceID]

		if !ok {
			// 该设备无权限记录
			item.UserPermType = pb.PermissionType_PERMISSION_TYPE_UNKNOWN
			devicePermList = append(devicePermList, item)
			continue
		}

		if req.UserId != "" {
			// 3.1 指定用户：返回该用户的权限类型
			item.UserPermType = pb.PermissionType_PERMISSION_TYPE_UNKNOWN
			for _, permItem := range permItems {
				if permItem.UserID == req.UserId {
					item.UserPermType = utils.StringToPermType(permItem.PermType)
					break
				}
			}
		} else {
			// 3.2 未指定用户：返回所有用户-权限映射
			userPermMap := make(map[string]pb.PermissionType)
			for _, permItem := range permItems {
				userPermMap[permItem.UserID] = utils.StringToPermType(permItem.PermType)
			}
			item.UserPermMap = userPermMap

			// 异步回写缓存
			go func(dID string, upMap map[string]pb.PermissionType) {
				// 转换为字符串map
				strMap := make(map[string]interface{})
				for uid, pt := range upMap {
					strMap[uid] = utils.PermTypeToString(pt)
				}
				if err := s.dao.HSetDevicePermsCache(dID, strMap); err != nil {
					s.log.Warn("Failed to write back device permission cache", "device_id", dID, "error", err)
				}
			}(deviceID, userPermMap)
		}

		devicePermList = append(devicePermList, item)
	}

	resp.DevicePermList = devicePermList
	return resp, nil

}

// ========== 辅助函数：判断权限类型是否在筛选列表中 ==========
func containsPermType(filter []pb.PermissionType, target pb.PermissionType) bool {
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
