package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/boqrs/comm/database/cache"
	"github.com/boqrs/iot-user-perm/pkg/model"
	pb "github.com/boqrs/iot-user-perm/pkg/proto"
	"github.com/boqrs/iot-user-perm/pkg/utils"
	"github.com/boqrs/zeus/log"
	logger "github.com/boqrs/zeus/log"
	"gorm.io/gorm"
)

type service struct {
	ch  *cacheService
	dao *daoService
	log log.Logger
}

func NewService(sql *gorm.DB, ch cache.Cache, l logger.Logger) Service {
	return &service{
		dao: newdaoService(sql, l),
		ch:  NewCacheService(ch, l),
		log: l.WithField("rpc", "service"),
	}
}

// ========== 1. 绑定设备（成为OWNER） ==========
func (s *service) BindDevice(ctx context.Context, req *pb.BindDeviceRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.UserId == "" || req.DeviceId == "" {
		return &pb.BaseResponse{
			Success: false,
			Code:    1,
			Msg:     "User ID or Device ID is missing",
		}, nil
	}

	// 3. 数据库操作
	if err := s.dao.CreateDeviceOwner(req.DeviceId, req.UserId); err != nil {
		return &pb.BaseResponse{
			Success: false,
			Code:    4,
			Msg:     err.Error(),
		}, nil
	}

	// 5. 更新缓存（永久有效）
	// 5.1 设置单用户-设备权限缓存
	_ = s.ch.SetUserDevicePermCache(req.UserId, req.DeviceId, "PERMISSION_TYPE_OWNER")
	// 5.2 设置设备OWNER缓存
	_ = s.ch.SetDeviceOwnerCache(req.DeviceId, req.UserId)
	// 5.3 添加用户设备列表缓存
	_ = s.ch.SAddUserDevicesCache(req.UserId, req.DeviceId)
	// 5.4 更新设备权限用户缓存
	permUsers := map[string][]string{
		"PERMISSION_TYPE_OWNER": {req.UserId},
	}
	_ = s.ch.UpdateDevicePermUsersCache(req.DeviceId, permUsers)

	// 6. 返回成功响应
	return &pb.BaseResponse{
		Success: true,
		Code:    0,
		Msg:     utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 2. 解绑设备（删除OWNER权限） ==========
func (s *service) UnbindDevice(ctx context.Context, req *pb.UnbindDeviceRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.UserId == "" || req.DeviceId == "" {
		return &pb.BaseResponse{
			Success: false,
			Code:    1,
			Msg:     "User ID or Device ID is missing",
		}, nil
	}

	// 3. 数据库操作
	if err := s.dao.DeleteDeviceOwner(req.DeviceId, req.UserId); err != nil {
		s.log.Errorf("Failed to delete device OWNER: %v", err)
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.DBError,
			Msg:     err.Error(),
		}, nil
	}

	// 5. 删除缓存
	// 5.1 删除单用户-设备权限缓存
	_ = s.ch.DelUserDevicePermCache(req.UserId, req.DeviceId)
	// 5.2 删除设备OWNER缓存
	_ = s.ch.DelDeviceOwnerCache(req.DeviceId)
	// 5.3 移除用户设备列表缓存
	_ = s.ch.SRemUserDevicesCache(req.UserId, req.DeviceId)
	_ = s.ch.DelEmptyUserDevicesCache(req.UserId)
	// 5.4 获取该设备的授权用户，批量删除其缓存
	authorizedUsers, _ := s.dao.GetAuthorizedUsers(req.DeviceId)
	for _, uId := range authorizedUsers {
		_ = s.ch.DelUserDevicePermCache(uId, req.DeviceId)
		_ = s.ch.SRemUserDevicesCache(uId, req.DeviceId)
		_ = s.ch.DelEmptyUserDevicesCache(uId)
	}
	// 5.5 删除设备权限用户缓存
	if err := s.ch.BatchDelDevicePermCache(req.DeviceId); err != nil {
		s.log.Errorf("failed to batch delete device perm cache, error: %s", err.Error())
	}

	// 6. 返回成功响应
	return &pb.BaseResponse{
		Success: true,
		Code:    utils.SuccessCode,
		Msg:     utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 3. 授权其他用户设备权限 ==========
func (s *service) AuthorizeDevicePermission(ctx context.Context, req *pb.AuthorizeDevicePermissionRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.OperatorName == "" || req.TargetUserId == "" || req.DeviceId == "" || req.PermType == pb.DevicePermType_DEVICE_PERM_UNKNOWN {
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError,
			Msg:     "The Authorizer ID, Grantee ID, Device ID, and Permission Type are required",
		}, nil
	}
	// 校验权限类型（仅VIEW/COMMAND）
	if req.PermType != pb.DevicePermType_DEVICE_PERM_COMMAND && req.PermType != pb.DevicePermType_DEVICE_PERM_VIEW {
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError,
			Msg:     "Only VIEW/COMMAND type permissions are supported for authorization",
		}, nil
	}
	// 校验授权方和被授权方不能是同一人
	if req.OperatorUserId == req.TargetUserId {
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError,
			Msg:     "The Authorizer and Grantee cannot be the same user",
		}, nil
	}

	// 3. 转换枚举为字符串
	permTypeStr := utils.PermTypeEnumToString(req.PermType)

	// 4. 数据库操作
	if err := s.dao.CreateAuthorizedPerm(req.OperatorUserId, req.TargetUserId, req.DeviceId, permTypeStr); err != nil {
		s.log.Errorf("Failed to create the authorization permission: %v", err)
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.DBError,
			Msg:     err.Error(),
		}, nil
	}

	// 6. 更新缓存
	// 6.1 设置被授权方单设备权限缓存
	_ = s.ch.SetUserDevicePermCache(req.TargetUserId, req.DeviceId, permTypeStr)
	// 6.2 添加被授权方设备列表缓存
	_ = s.ch.SAddUserDevicesCache(req.TargetUserId, req.DeviceId)
	// 6.3 更新设备权限用户缓存
	permUsers, _ := s.dao.GetDeviceAllPermUsers(req.DeviceId)
	_ = s.ch.UpdateDevicePermUsersCache(req.DeviceId, permUsers)

	// 7. 返回成功响应
	return &pb.BaseResponse{
		Success: true,
		Code:    utils.SuccessCode,
		Msg:     utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 4. 撤销其他用户设备权限 ==========
func (s *service) RevokeDevicePermission(ctx context.Context, req *pb.RevokeDevicePermissionRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.OperatorUserId == "" || req.TargetUserId == "" || req.DeviceId == "" || req.PermType == pb.DevicePermType_DEVICE_PERM_UNKNOWN {
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError,
			Msg:     "The Authorizer ID, Grantee ID, Device ID, and Permission Type cannot be empty",
		}, nil
	}

	// 3. 转换枚举为字符串
	permTypeStr := utils.PermTypeEnumToString(req.PermType)

	// 4. 数据库操作
	if err := s.dao.DeleteAuthorizedPerm(req.TargetUserId, req.TargetUserId, req.DeviceId, permTypeStr); err != nil {
		s.log.Errorf("Failed to delete the authorization permission: %v", err)
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.DBError,
			Msg:     err.Error(),
		}, nil
	}

	// 6. 删除缓存
	// 6.1 删除被授权方单设备权限缓存
	_ = s.ch.DelUserDevicePermCache(req.TargetUserId, req.DeviceId)
	// 6.2 移除被授权方设备列表缓存
	_ = s.ch.SRemUserDevicesCache(req.TargetUserId, req.DeviceId)
	_ = s.ch.DelEmptyUserDevicesCache(req.TargetUserId)
	// 6.3 更新设备权限用户缓存
	permUsers, _ := s.dao.GetDeviceAllPermUsers(req.DeviceId)
	_ = s.ch.UpdateDevicePermUsersCache(req.DeviceId, permUsers)

	// 7. 返回成功响应
	return &pb.BaseResponse{
		Success: true,
		Code:    utils.SuccessCode,
		Msg:     utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 5. 查询用户设备权限 ==========
func (s *service) GetDevicePermission(ctx context.Context, req *pb.GetDevicePermissionRequest) (*pb.GetDevicePermissionResponse, error) {
	// 1. 参数校验
	if req.UserId == "" || req.DeviceId == "" {
		return &pb.GetDevicePermissionResponse{
			BaseResp: &pb.BaseResponse{
				Success: false,
				Code:    utils.ParamError,
				Msg:     "The Authorizer ID, Grantee ID, Device ID, and Permission Type are required",
			},
			PermType: pb.DevicePermType_DEVICE_PERM_UNKNOWN,
		}, nil
	}

	// 2. 查缓存
	permTypeStr, err := s.dao.GetUserDevicePerm(req.UserId, req.DeviceId)
	if err == nil {
		// 刷新缓存为永久有效
		key := fmt.Sprintf(KeyUserDevicePerm, req.UserId, req.DeviceId)
		_ = s.ch.RefreshPermCache(key)
		// 转换字符串为枚举
		permType := utils.StringToPermTypeEnum(permTypeStr)
		return &pb.GetDevicePermissionResponse{
			BaseResp: &pb.BaseResponse{
				Success: true,
				Code:    utils.SuccessCode,
				Msg:     utils.ErrorMsg[utils.SuccessCode],
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
				Success: false,
				Code:    utils.DBError,
				Msg:     fmt.Sprintf("Failed to query user device permissions: %v", err),
			},
			PermType: pb.DevicePermType_DEVICE_PERM_UNKNOWN,
		}, nil
	}

	// 4. 回写缓存（永久有效）
	_ = s.ch.SetUserDevicePermCache(req.UserId, req.DeviceId, permTypeStr)

	// 5. 转换字符串为枚举
	permType := utils.StringToPermTypeEnum(permTypeStr)

	// 6. 返回响应
	return &pb.GetDevicePermissionResponse{
		BaseResp: &pb.BaseResponse{
			Success: true,
			Code:    utils.SuccessCode,
			Msg:     utils.ErrorMsg[utils.SuccessCode],
		},
		PermType: permType,
	}, nil
}

// ========== 6. 批量删除设备所有权限 ==========
func (s *service) BatchDeleteDevicePermission(ctx context.Context, req *pb.BatchDeleteDevicePermissionRequest) (*pb.BaseResponse, error) {
	// 1. 参数校验
	if req.DeviceId == "" {
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError,
			Msg:     "Device ID cannot be empty",
		}, nil
	}

	// 3. 数据库操作
	if err := s.dao.BatchDeleteDevicePerm(req.DeviceId); err != nil {
		s.log.Errorf("Batch deletion of device permissions failed: %v", err)
		return &pb.BaseResponse{
			Success: false,
			Code:    utils.DBError,
			Msg:     err.Error(),
		}, nil
	}

	// 5. 批量删除缓存
	_ = s.ch.BatchDelDevicePermCache(req.DeviceId)

	// 6. 返回成功响应
	return &pb.BaseResponse{
		Success: true,
		Code:    utils.SuccessCode,
		Msg:     utils.ErrorMsg[utils.SuccessCode],
	}, nil
}

// ========== 7. 查询设备的所有权限用户列表 ==========
func (s *service) GetDevicePermissionUsers(ctx context.Context, req *pb.GetDevicePermissionUsersRequest) (*pb.GetDevicePermissionUsersResponse, error) {
	resp := &pb.GetDevicePermissionUsersResponse{
		BaseResp: &pb.BaseResponse{
			Success: true,
			Code:    utils.SuccessCode,
			Msg:     utils.ErrorMsg[utils.SuccessCode],
		},
	}

	// 1. 参数校验
	if req.DeviceId == "" {
		resp.BaseResp = &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError,
			Msg:     "device id should not be empty",
		}
		return resp, nil
	}

	// 2. 判断是否需要返回所有用户
	if req.NeedAll {
		// 2.1 查缓存Set
		userIDs, err := s.ch.GetDevicePermUsersSetCache(req.DeviceId)
		if err == nil && len(userIDs) > 0 {
			// 刷新缓存为永久有效
			key := fmt.Sprintf(KeyDevicePermUsersSet, req.DeviceId)
			_ = s.ch.RefreshPermCache(key)
			resp.AllUserIds = userIDs
			return resp, nil
		}

		// 2.2 缓存未命中，查数据库
		permUsers, err := s.dao.GetDeviceAllPermUsers(req.DeviceId)
		if err != nil {
			s.log.Errorf("Failed to query all users with permissions on the device: %v", err)
			resp.BaseResp = &pb.BaseResponse{
				Success: false,
				Code:    utils.DBError,
				Msg:     fmt.Sprintf("查询设备所有权限用户失败: %v", err),
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
			_ = s.ch.UpdateDevicePermUsersCache(req.DeviceId, permUsers)
		}()

		return resp, nil
	}

	// 3. 按类型分类返回
	// 3.1 查缓存Hash

	permUserHash, err := s.ch.GetDevicePermUsersHashCache(req.DeviceId)
	if err == nil && len(permUserHash) > 0 {
		// 刷新缓存为永久有效
		key := fmt.Sprintf(KeyDevicePermUsersHash, req.DeviceId)
		_ = s.ch.RefreshPermCache(key)

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
			Success: false,
			Code:    utils.DBError,
			Msg:     fmt.Sprintf("查询设备所有权限用户失败: %v", err),
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
		_ = s.ch.UpdateDevicePermUsersCache(req.DeviceId, permUsers)
	}()

	return resp, nil
}

// ========== 8. 查询设备的所有权限用户列表 ==========
func (s *service) BatchGetUserDevices(ctx context.Context, req *pb.BatchGetUserDevicesRequest) (*pb.BatchGetUserDevicesResponse, error) {
	resp := &pb.BatchGetUserDevicesResponse{
		BaseResp: &pb.BaseResponse{
			Success: true,
			Code:    utils.SuccessCode,
			Msg:     "",
		},
	}

	// 1. 参数校验
	if req.UserId == "" {
		resp.BaseResp = &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError, // 参数错误
			Msg:     "user_id should not be empty",
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

	filterPermStrs := utils.PermTypesToStrings(req.PermTypes)

	// 3. 优先查缓存（用户设备列表）
	deviceIDs, err := s.ch.SMembersUserDevicesCache(req.UserId)
	if err != nil {
		s.log.Warn("Failed to query user device cache", "user_id", req.UserId, "error", err)
	} else if len(deviceIDs) > 0 {
		// 缓存命中：刷新缓存过期时间
		cacheKey := fmt.Sprintf(KeyUserDevices, req.UserId)
		_ = s.ch.RefreshCache(cacheKey)

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
			Success: false,
			Code:    utils.DBError, // 数据库错误
			Msg:     fmt.Sprintf("query failed: %v", err),
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
		if err := s.ch.SAddUserDevicesCache(req.UserId, deviceIDSet...); err != nil {
			s.log.Warn("Failed to write back user device cache", "user_id", req.UserId, "error", err)
		}
	}()

	return resp, nil

}

func (s *service) BatchGetDevicePerms(ctx context.Context, req *pb.BatchGetDevicePermsRequest) (*pb.BatchGetDevicePermsResponse, error) {
	// 初始化响应
	resp := &pb.BatchGetDevicePermsResponse{
		BaseResp: &pb.BaseResponse{
			Success: true,
			Code:    utils.SuccessCode,
			Msg:     "",
		},
	}

	// 1. 参数校验
	if len(req.DeviceIds) == 0 {
		resp.BaseResp = &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError, // 参数错误
			Msg:     "device_ids should not be empty",
		}
		return resp, nil
	}
	if len(req.DeviceIds) > 100 { // 限制批量查询数量，防止性能问题
		resp.BaseResp = &pb.BaseResponse{
			Success: false,
			Code:    utils.ParamError,
			Msg:     "device_ids must be lower than 100",
		}
		return resp, nil
	}

	// 2. 批量查询数据库
	devicePermMap, err := s.dao.BatchGetDevicePerms(req.DeviceIds, req.UserId)
	if err != nil {
		s.log.Error("批量查询设备权限失败", "device_ids", req.DeviceIds, "user_id", req.UserId, "error", err)
		resp.BaseResp = &pb.BaseResponse{
			Success: false,
			Code:    utils.DBError, // 数据库错误
			Msg:     fmt.Sprintf("查询失败: %v", err),
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
			item.UserPermType = pb.DevicePermType_DEVICE_PERM_UNKNOWN
			devicePermList = append(devicePermList, item)
			continue
		}

		if req.UserId != "" {
			// 3.1 指定用户：返回该用户的权限类型
			item.UserPermType = pb.DevicePermType_DEVICE_PERM_UNKNOWN
			for _, permItem := range permItems {
				if permItem.UserID == req.UserId {
					item.UserPermType = utils.StringToPermType(permItem.PermType)
					break
				}
			}
		} else {
			// 3.2 未指定用户：返回所有用户-权限映射
			userPermMap := make(map[string]pb.DevicePermType)
			for _, permItem := range permItems {
				userPermMap[permItem.UserID] = utils.StringToPermType(permItem.PermType)
			}
			item.UserPermMap = userPermMap

			// 异步回写缓存
			go func(dID string, upMap map[string]pb.DevicePermType) {
				// 转换为字符串map
				strMap := make(map[string]interface{})
				for uid, pt := range upMap {
					strMap[uid] = utils.PermTypeToString(pt)
				}
				if err := s.ch.HSetDevicePermsCache(dID, strMap); err != nil {
					s.log.Warn("Failed to write back device permission cache", "device_id", dID, "error", err)
				}
			}(deviceID, userPermMap)
		}

		devicePermList = append(devicePermList, item)
	}

	resp.DevicePermList = devicePermList
	return resp, nil

}

// AddApiPerm 新增API权限
func (s *service) AddApiPerm(ctx context.Context, req *pb.AddApiPermRequest) (*pb.BaseResponse, error) {
	// 步骤1：RequestID + 参数校验
	requestID := getRequestID(ctx)
	if req.OperatorUserId == "" || req.OperIp == "" || req.ApiPerm == nil || req.ApiPerm.PermId == "" || req.ApiPerm.PermName == "" || req.ApiPerm.ApiPath == "" || req.ApiPerm.ApiMethod == pb.HttpMethod_HTTP_METHOD_UNKNOWN {
		errMsg := "param error：操作人ID/操作IP/API权限信息不能为空，PermID/名称/路径/方法为必选"
		logger.Warn("[AddApiPerm]failed to check param", "requestID", requestID, "err", errMsg)
		//s.recordOperLog(ctx, requestID, req, pb.OperResult_OPER_RESULT_FAIL, errMsg)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤2：检查PermID是否已存在（唯一索引，避免重复）
	exist, err := s.dao.CheckPermIDExist(req.ApiPerm.PermId)
	if err != nil {
		errMsg := "检查PermID是否存在失败：" + err.Error()
		logger.Errorf("[AddApiPerm]DAO查询失败", "requestID", requestID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	if exist {
		errMsg := "PermID已存在：" + req.ApiPerm.PermId + "，请更换唯一PermID"
		logger.Warnf("[AddApiPerm]PermID重复", "requestID", requestID, "permID", req.ApiPerm.PermId)
		return &pb.BaseResponse{
			Success:   false,
			Code:      5,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤3：转换Proto为Model
	apiPermModel := &model.PermissionApi{
		PermID:    req.ApiPerm.PermId,
		PermName:  req.ApiPerm.PermName,
		ApiPath:   req.ApiPerm.ApiPath,
		ApiMethod: req.ApiPerm.ApiMethod.String(),
		Remark:    req.ApiPerm.Remark,
	}

	// 步骤4：数据库操作
	if err := s.dao.CreateApiPerm(apiPermModel); err != nil {
		errMsg := "新增API权限失败：" + err.Error()
		logger.Error("[AddApiPerm]CreateApiPerm失败", "requestID", requestID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤5：缓存更新（序列化Model为JSON存入缓存）
	apiPermJson, _ := json.Marshal(apiPermModel) // 序列化失败仅日志，不影响主流程
	if err = s.ch.SetApiPerm(req.ApiPerm.PermId, string(apiPermJson), -1); err != nil {
		logger.Warn("[AddApiPerm]缓存更新失败", "requestID", requestID, "permID", req.ApiPerm.PermId, "err", err)
	}

	// 步骤6：记录日志 + 返回响应
	logger.Info("[AddApiPerm]API权限新增成功", "requestID", requestID, "permID", req.ApiPerm.PermId)
	return &pb.BaseResponse{
		Success:   true,
		Code:      0,
		Msg:       "API权限新增成功",
		RequestId: requestID,
	}, nil
}

func (s *service) AddRole(ctx context.Context, req *pb.AddRoleRequest) (*pb.BaseResponse, error) {
	// 步骤1：RequestID + 参数校验
	requestID := getRequestID(ctx)
	if req.OperatorUserId == "" || req.OperIp == "" || req.Role == nil || req.Role.RoleCode == "" || req.Role.RoleName == "" {
		errMsg := "参数错误：操作人ID/操作IP/角色信息不能为空，角色编码/名称为必选"
		logger.Warn("[AddRole]参数校验失败", "requestID", requestID, "err", errMsg)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤2：检查RoleCode是否已存在（唯一索引）
	exist, err := s.dao.CheckRoleCodeExist(req.Role.RoleCode)
	if err != nil {
		errMsg := "检查角色编码是否存在失败：" + err.Error()
		logger.Error("[AddRole]DAO查询失败", "requestID", requestID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	if exist {
		errMsg := "角色编码已存在：" + req.Role.RoleCode + "，请更换唯一角色编码"
		logger.Warn("[AddRole]RoleCode重复", "requestID", requestID, "roleCode", req.Role.RoleCode)
		return &pb.BaseResponse{
			Success:   false,
			Code:      5,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤3：Proto转Model
	roleModel := &model.PermissionRole{
		RoleCode: req.Role.RoleCode,
		RoleName: req.Role.RoleName,
		Remark:   req.Role.Remark,
	}

	// 步骤4：数据库操作
	if err := s.dao.CreateRole(roleModel); err != nil {
		errMsg := "新增角色失败：" + err.Error()
		logger.Error("[AddRole]CreateRole失败", "requestID", requestID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤5：缓存更新（序列化角色为JSON）
	roleJson, _ := json.Marshal(roleModel)
	if err := s.ch.SetRole(req.Role.RoleCode, string(roleJson)); err != nil {
		logger.Warn("[AddRole]缓存更新失败", "requestID", requestID, "roleCode", req.Role.RoleCode, "err", err)
	}

	// 步骤6：记录日志 + 返回响应
	logger.Info("[AddRole]角色新增成功", "requestID", requestID, "roleCode", req.Role.RoleCode)
	return &pb.BaseResponse{
		Success:   true,
		Code:      0,
		Msg:       "角色新增成功",
		RequestId: requestID,
	}, nil
}

// BindRoleApi 角色绑定API权限（批量）
func (s *service) BindRoleApi(ctx context.Context, req *pb.BindRoleApiRequest) (*pb.BaseResponse, error) {
	// 步骤1：RequestID + 参数校验
	requestID := getRequestID(ctx)
	if req.OperatorUserId == "" || req.OperIp == "" || req.RoleCode == "" || len(req.PermIds) == 0 {
		errMsg := "参数错误：操作人ID/操作IP/角色编码不能为空，且至少选择一个API权限ID"
		logger.Warn("[BindRoleApi]参数校验失败", "requestID", requestID, "err", errMsg)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤2：批量检查角色-API权限是否已存在（避免重复绑定）
	var existPermIDs []string
	for _, permID := range req.PermIds {
		exist, err := s.dao.CheckRoleApiExist(req.RoleCode, permID)
		if err != nil {
			errMsg := "检查角色-API权限是否存在失败：" + err.Error()
			logger.Error("[BindRoleApi]DAO查询失败", "requestID", requestID, "permID", permID, "err", err)
			return &pb.BaseResponse{
				Success:   false,
				Code:      4,
				Msg:       errMsg,
				RequestId: requestID,
			}, nil
		}
		if exist {
			existPermIDs = append(existPermIDs, permID)
		}
	}
	// 若存在重复，返回提示
	if len(existPermIDs) > 0 {
		errMsg := "部分API权限已绑定该角色：" + joinSlice(existPermIDs, ",")
		logger.Warn("[BindRoleApi]权限已绑定", "requestID", requestID, "roleCode", req.RoleCode, "existPermIDs", existPermIDs)
		return &pb.BaseResponse{
			Success:   false,
			Code:      5,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤3：构造批量绑定Model
	var roleApiModels []*model.PermissionRoleApi
	for _, permID := range req.PermIds {
		roleApiModels = append(roleApiModels, &model.PermissionRoleApi{
			RoleCode: req.RoleCode,
			PermID:   permID,
		})
	}

	// 步骤4：开启事务（批量操作，原子性）
	// 步骤5：批量插入数据库
	if err := s.dao.BatchCreateRoleApi(roleApiModels); err != nil {
		errMsg := "批量绑定角色-API权限失败：" + err.Error()
		logger.Error("[BindRoleApi]BatchCreateRoleApi失败", "requestID", requestID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 步骤6：缓存更新（向角色-API权限Set添加批量PermID）
	if err := s.ch.SAddRoleApiPerms(req.RoleCode, req.PermIds...); err != nil {
		logger.Warn("[BindRoleApi]缓存更新失败", "requestID", requestID, "roleCode", req.RoleCode, "err", err)
	}

	// 步骤7：记录日志 + 返回响应
	logger.Info("[BindRoleApi]角色-API权限批量绑定成功", "requestID", requestID, "roleCode", req.RoleCode, "permIDCount", len(req.PermIds))
	return &pb.BaseResponse{
		Success:   true,
		Code:      0,
		Msg:       "角色-API权限批量绑定成功",
		RequestId: requestID,
	}, nil
}

// UpdateApiPerm 更新API权限
func (s *service) UpdateApiPerm(ctx context.Context, req *pb.UpdateApiPermRequest) (*pb.BaseResponse, error) {
	// 1. RequestID获取 + 基础参数校验
	requestID := getRequestID(ctx)
	if req.OperatorUserId == "" || req.OperIp == "" || req.ApiPerm == nil || req.ApiPerm.PermId == "" {
		errMsg := "参数错误：操作人ID/操作IP/API权限信息不能为空，PermID为必选"
		logger.Warn("[UpdateApiPerm]参数校验失败", "requestID", requestID, "err", errMsg)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	permID := req.ApiPerm.PermId

	// 2. 检查API权限是否存在（未软删除）
	exist, err := s.dao.CheckPermIDExist(permID)
	if err != nil {
		errMsg := "检查API权限是否存在失败：" + err.Error()
		logger.Error("[UpdateApiPerm]DAO查询失败", "requestID", requestID, "permID", permID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	if !exist {
		errMsg := "API权限不存在：" + permID
		logger.Warn("[UpdateApiPerm]资源不存在", "requestID", requestID, "permID", permID)
		return &pb.BaseResponse{
			Success:   false,
			Code:      2,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 3. 检查是否为内置权限（禁止修改核心字段）
	if IsBuiltInApiPerm(permID) {
		errMsg := "操作不允许：禁止修改系统内置API权限"
		logger.Warn("[UpdateApiPerm]修改内置权限", "requestID", requestID, "permID", permID)
		return &pb.BaseResponse{
			Success:   false,
			Code:      7,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 4. 构造更新条件和数据（仅更新非空字段，避免覆盖原有值）
	updateData := make(map[string]interface{})
	if req.ApiPerm.PermName != "" {
		updateData["perm_name"] = req.ApiPerm.PermName
	}
	if req.ApiPerm.ApiPath != "" {
		updateData["api_path"] = req.ApiPerm.ApiPath
	}
	if req.ApiPerm.ApiMethod != pb.HttpMethod_HTTP_METHOD_UNKNOWN {
		updateData["api_method"] = req.ApiPerm.ApiMethod.String()
	}
	if req.ApiPerm.Remark != "" {
		updateData["remark"] = req.ApiPerm.Remark
	}
	if len(updateData) == 0 {
		errMsg := "参数错误：无有效更新字段"
		logger.Warn("[UpdateApiPerm]无更新字段", "requestID", requestID, "permID", permID)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	updateData["updated_at"] = gorm.Expr("NOW()")

	// 5. 数据库更新操作（软删除的记录不更新）
	if err = s.dao.UpdatePermissionApi(updateData); err != nil {
		errMsg := "更新API权限失败：" + err.Error()
		logger.Error("[UpdateApiPerm]DB更新失败", "requestID", requestID, "permID", permID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 6. 查询最新数据，更新缓存（保证缓存与DB一致）
	//var latestApiPerm model.PermissionApi
	latestApiPerm, err := s.dao.GetPermissionApi(permID)
	if err != nil {
		logger.Warn("[UpdateApiPerm]查询最新数据失败，缓存未更新", "requestID", requestID, "permID", permID, "err", err)
	} else {
		apiPermJson, _ := json.Marshal(&latestApiPerm)
		if err := s.ch.SetApiPerm(permID, string(apiPermJson), -1); err != nil {
			logger.Warn("[UpdateApiPerm]缓存更新失败", "requestID", requestID, "permID", permID, "err", err)
		}
	}

	// 7. 异步日志 + 成功响应
	logger.Info("[UpdateApiPerm]API权限更新成功", "requestID", requestID, "permID", permID)
	return &pb.BaseResponse{
		Success:   true,
		Code:      0,
		Msg:       "API权限更新成功",
		RequestId: requestID,
	}, nil
}

func (s *service) DeleteApiPerm(ctx context.Context, req *pb.DeleteApiPermRequest) (*pb.BaseResponse, error) {
	// 1. RequestID + 参数校验
	requestID := getRequestID(ctx)
	if req.OperatorUserId == "" || req.OperIp == "" || req.PermId == "" {
		errMsg := "参数错误：操作人ID/操作IP/API权限ID不能为空"
		logger.Warn("[DeleteApiPerm]参数校验失败", "requestID", requestID, "err", errMsg)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	permID := req.PermId

	// 2. 检查是否为内置权限（禁止删除）
	if IsBuiltInApiPerm(permID) {
		errMsg := "操作不允许：禁止删除系统内置API权限"
		logger.Warn("[DeleteApiPerm]删除内置权限", "requestID", requestID, "permID", permID)
		return &pb.BaseResponse{
			Success:   false,
			Code:      7,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 3. 检查API权限是否存在
	exist, err := s.dao.CheckPermIDExist(permID)
	if err != nil {
		errMsg := "检查API权限是否存在失败：" + err.Error()
		logger.Error("[DeleteApiPerm]DAO查询失败", "requestID", requestID, "permID", permID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	if !exist {
		errMsg := "API权限不存在：" + permID
		logger.Warn("[DeleteApiPerm]资源不存在", "requestID", requestID, "permID", permID)
		return &pb.BaseResponse{
			Success:   false,
			Code:      2,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 4. 数据库软删除操作（GORM Delete方法自动更新DeletedAt）
	if err = s.dao.DeletePermissionApi(permID); err != nil {
		errMsg := "软删除API权限失败：" + err.Error()
		logger.Error("[DeleteApiPerm]DB软删除失败", "requestID", requestID, "permID", permID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 5. 删除对应缓存（避免脏数据）
	cacheKey := fmt.Sprintf("iot:api:perm:%s", permID)
	if err = s.ch.DelRoleApi(cacheKey); err != nil {
		logger.Warn("[DeleteApiPerm]缓存删除失败", "requestID", requestID, "permID", permID, "err", err)
	}

	// 6. 异步日志 + 成功响应
	logger.Info("[DeleteApiPerm]API权限软删除成功", "requestID", requestID, "permID", permID)
	return &pb.BaseResponse{
		Success:   true,
		Code:      0,
		Msg:       "API权限删除成功",
		RequestId: requestID,
	}, nil
}

// ListApiPerm API权限列表查询
func (s *service) ListApiPerm(ctx context.Context, req *pb.ListApiPermRequest) (*pb.ListApiPermResponse, error) {
	// 1. RequestID + 解析分页参数
	requestID := getRequestID(ctx)
	page, size := ParsePageParam(req.Page)

	// 5. 构造返回结果
	total, apiPermList, err := s.dao.PermissionApiList(requestID, req)
	if err != nil {
		return nil, err
	}
	//pageInfo := CalcPageInfo(total, page, size)
	protoList := ApiPermModelsToProtos(apiPermList)
	logger.Info("[ListApiPerm]API权限列表查询成功", "requestID", requestID, "total", total, "page", page, "size", size)
	return &pb.ListApiPermResponse{
		BaseResp: &pb.BaseResponse{
			Success:   true,
			Code:      0,
			Msg:       "查询成功",
			RequestId: requestID,
		},
		Total:       total,
		ApiPermList: protoList,
	}, nil
}

// UpdateRole 更新角色
func (s *service) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.BaseResponse, error) {
	// 1. RequestID + 参数校验
	requestID := getRequestID(ctx)
	if req.OperatorUserId == "" || req.OperIp == "" || req.Role == nil || req.Role.RoleCode == "" {
		errMsg := "参数错误：操作人ID/操作IP/角色信息不能为空，角色编码为必选"
		logger.Warn("[UpdateRole]参数校验失败", "requestID", requestID, "err", errMsg)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	roleCode := req.Role.RoleCode

	// 2. 检查角色是否存在
	exist, err := s.dao.CheckRoleCodeExist(roleCode)
	if err != nil {
		errMsg := "检查角色是否存在失败：" + err.Error()
		logger.Error("[UpdateRole]DAO查询失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	if !exist {
		errMsg := "角色不存在：" + roleCode
		logger.Warn("[UpdateRole]资源不存在", "requestID", requestID, "roleCode", roleCode)
		return &pb.BaseResponse{
			Success:   false,
			Code:      2,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 3. 检查是否为内置角色（禁止修改）
	if IsBuiltInRole(roleCode) {
		errMsg := "操作不允许：禁止修改系统内置角色"
		logger.Warn("[UpdateRole]修改内置角色", "requestID", requestID, "roleCode", roleCode)
		return &pb.BaseResponse{
			Success:   false,
			Code:      7,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 4. 构造更新数据（仅更新非空字段）
	updateData := make(map[string]interface{})
	if req.Role.RoleName != "" {
		updateData["role_name"] = req.Role.RoleName
	}
	if req.Role.Remark != "" {
		updateData["remark"] = req.Role.Remark
	}
	if len(updateData) == 0 {
		errMsg := "参数错误：无有效更新字段"
		logger.Warn("[UpdateRole]无更新字段", "requestID", requestID, "roleCode", roleCode)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	updateData["updated_at"] = gorm.Expr("NOW()")

	// 5. 数据库更新
	if err = s.dao.UpdatePermRole(updateData); err != nil {
		errMsg := "更新角色失败：" + err.Error()
		logger.Error("[UpdateRole]DB更新失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 6. 查询最新数据，更新缓存
	var latestRole *model.PermissionRole
	if latestRole, err = s.dao.GetPermRole(roleCode); err != nil {
		logger.Warn("[UpdateRole]查询最新数据失败，缓存未更新", "requestID", requestID, "roleCode", roleCode, "err", err)
	} else {
		roleJson, _ := json.Marshal(&latestRole)
		if err = s.ch.UpdateRole(roleCode, string(roleJson)); err != nil {
			logger.Warn("[UpdateRole]缓存更新失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		}
	}

	logger.Info("[UpdateRole]角色更新成功", "requestID", requestID, "roleCode", roleCode)
	return &pb.BaseResponse{
		Success:   true,
		Code:      0,
		Msg:       "角色更新成功",
		RequestId: requestID,
	}, nil
}

// DeleteRole 软删除角色，级联软删除角色-API绑定
func (s *service) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*pb.BaseResponse, error) {
	// 1. RequestID + 参数校验
	requestID := getRequestID(ctx)
	if req.OperatorUserId == "" || req.OperIp == "" || req.RoleCode == "" {
		errMsg := "参数错误：操作人ID/操作IP/角色编码不能为空"
		logger.Warn("[DeleteRole]参数校验失败", "requestID", requestID, "err", errMsg)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	roleCode := req.RoleCode

	// 2. 检查是否为内置角色（禁止删除）
	if IsBuiltInRole(roleCode) {
		errMsg := "操作不允许：禁止删除系统内置角色"
		logger.Warn("[DeleteRole]删除内置角色", "requestID", requestID, "roleCode", roleCode)
		return &pb.BaseResponse{
			Success:   false,
			Code:      7,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 3. 检查角色是否存在
	exist, err := s.dao.CheckRoleCodeExist(roleCode)
	if err != nil {
		errMsg := "检查角色是否存在失败：" + err.Error()
		logger.Error("[DeleteRole]DAO查询失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	if !exist {
		errMsg := "角色不存在：" + roleCode
		logger.Warn("[DeleteRole]资源不存在", "requestID", requestID, "roleCode", roleCode)
		return &pb.BaseResponse{
			Success:   false,
			Code:      2,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	if err = s.dao.DelPermRole(roleCode); err != nil {
		errMsg := "删除失败：" + err.Error()
		logger.Error("[DeleteRole]角色删除失败", "requestID", requestID, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 8. 删除角色相关所有缓存
	cacheKeys := []string{
		fmt.Sprintf(KeyPermRole, roleCode),     // 角色基础信息缓存
		fmt.Sprintf(KeyPermRoleApis, roleCode), // 角色-API权限Set缓存
	}
	if err = s.ch.DelRoles(cacheKeys...); err != nil {
		logger.Warn("[DeleteRole]部分缓存删除失败", "requestID", requestID, "roleCode", roleCode, "err", err)
	}

	// 9. 日志 + 响应
	logger.Info("[DeleteRole]角色软删除成功，已级联删除API权限绑定", "requestID", requestID, "roleCode", roleCode)
	return &pb.BaseResponse{
		Success:   true,
		Code:      0,
		Msg:       "角色删除成功",
		RequestId: requestID,
	}, nil
}

// ListRole 角色列表查询
func (s *service) ListRole(ctx context.Context, req *pb.ListRoleRequest) (*pb.ListRoleResponse, error) {
	// 1. RequestID + 解析分页参数
	requestID := getRequestID(ctx)
	page, size := ParsePageParam(req.Page)
	//offset := (page - 1) * size
	total, roleList, err := s.dao.ListRole(requestID, req)
	if err != nil {
		errMsg := "查询失败：" + err.Error()
		logger.Error("[DeleteRole]角色删除失败", "requestID", requestID, "err", err)
		return &pb.ListRoleResponse{
			BaseResp: &pb.BaseResponse{
				Success:   true,
				Code:      4,
				Msg:       errMsg,
				RequestId: requestID,
			},
			Total:    total,
			RoleList: roleList,
		}, nil
	}
	// 5. 构造返回结果
	logger.Info("[ListRole]角色列表查询成功", "requestID", requestID, "total", total, "page", page, "size", size)
	return &pb.ListRoleResponse{
		BaseResp: &pb.BaseResponse{
			Success:   true,
			Code:      0,
			Msg:       "查询成功",
			RequestId: requestID,
		},
		Total:    total,
		RoleList: roleList,
	}, nil
}

// UnbindRoleApi 批量解绑角色-API权限
func (s *service) UnbindRoleApi(ctx context.Context, req *pb.UnbindRoleApiRequest) (*pb.BaseResponse, error) {
	// 1. RequestID + 参数校验
	requestID := getRequestID(ctx)
	if req.OperatorUserId == "" || req.OperIp == "" || req.RoleCode == "" || len(req.PermIds) == 0 {
		errMsg := "参数错误：操作人ID/操作IP/角色编码不能为空，且至少选择一个API权限ID"
		logger.Warn("[UnbindRoleApi]参数校验失败", "requestID", requestID, "err", errMsg)
		return &pb.BaseResponse{
			Success:   false,
			Code:      1,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	roleCode := req.RoleCode
	permIDs := req.PermIds

	// 2. 检查角色是否存在
	roleExist, err := s.dao.CheckRoleCodeExist(roleCode)
	if err != nil {
		errMsg := "检查角色是否存在失败：" + err.Error()
		logger.Error("[UnbindRoleApi]检查角色失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}
	if !roleExist {
		errMsg := "角色不存在：" + roleCode
		logger.Warn("[UnbindRoleApi]角色不存在", "requestID", requestID, "roleCode", roleCode)
		return &pb.BaseResponse{
			Success:   false,
			Code:      2,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 3. 批量检查绑定关系是否存在
	var notExistPermIDs []string
	for _, permID := range permIDs {
		exist, err := s.dao.CheckRoleApiExist(roleCode, permID)
		if err != nil {
			errMsg := "检查角色-API绑定关系失败：" + err.Error()
			logger.Error("[UnbindRoleApi]检查绑定失败", "requestID", requestID, "roleCode", roleCode, "permID", permID, "err", err)
			return &pb.BaseResponse{
				Success:   false,
				Code:      4,
				Msg:       errMsg,
				RequestId: requestID,
			}, nil
		}
		if !exist {
			notExistPermIDs = append(notExistPermIDs, permID)
		}
	}
	if len(notExistPermIDs) > 0 {
		errMsg := "部分API权限未绑定该角色：" + joinSlice(notExistPermIDs, ",")
		logger.Warn("[UnbindRoleApi]绑定关系不存在", "requestID", requestID, "roleCode", roleCode, "notExistPermIDs", notExistPermIDs)
		return &pb.BaseResponse{
			Success:   false,
			Code:      2,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	if err = s.dao.DelPermRoleApi(roleCode, permIDs); err != nil {
		errMsg := "批量软删除绑定关系失败：" + err.Error()
		logger.Error("[UnbindRoleApi]批量删除失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		return &pb.BaseResponse{
			Success:   false,
			Code:      4,
			Msg:       errMsg,
			RequestId: requestID,
		}, nil
	}

	// 7. 更新缓存：从角色-API权限Set中移除对应PermID
	cacheKey := fmt.Sprintf(KeyPermRoleApis, roleCode)
	if err = s.ch.DelRoleApis(cacheKey, permIDs...); err != nil { // 补充SRem方法到CacheService
		logger.Warn("[UnbindRoleApi]缓存更新失败", "requestID", requestID, "roleCode", roleCode, "err", err)
	}

	// 8. 日志 + 响应
	logger.Info("[UnbindRoleApi]角色-API权限批量解绑成功", "requestID", requestID, "roleCode", roleCode, "permIDCount", len(permIDs))
	return &pb.BaseResponse{
		Success:   true,
		Code:      0,
		Msg:       "角色-API权限批量解绑成功",
		RequestId: requestID,
	}, nil
}

// ListRoleApi 查询角色绑定的API权限列表
func (s *service) ListRoleApi(ctx context.Context, req *pb.ListRoleApiRequest) (*pb.ListRoleApiResponse, error) {
	// 1. RequestID + 参数校验
	requestID := getRequestID(ctx)
	if req.RoleCode == "" {
		errMsg := "参数错误：角色编码不能为空"
		logger.Warn("[ListRoleApi]参数校验失败", "requestID", requestID, "err", errMsg)
		return &pb.ListRoleApiResponse{
			BaseResp: &pb.BaseResponse{
				Success:   false,
				Code:      1,
				Msg:       errMsg,
				RequestId: requestID,
			},
		}, nil
	}
	roleCode := req.RoleCode
	//page, size := ParsePageParam(req.Page)
	//offset := (page - 1) * size

	// 2. 检查角色是否存在
	exist, err := s.dao.CheckRoleCodeExist(roleCode)
	if err != nil {
		errMsg := "检查角色是否存在失败：" + err.Error()
		logger.Error("[ListRoleApi]检查角色失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		return &pb.ListRoleApiResponse{
			BaseResp: &pb.BaseResponse{
				Success:   false,
				Code:      4,
				Msg:       errMsg,
				RequestId: requestID,
			},
		}, nil
	}
	if !exist {
		errMsg := "角色不存在：" + roleCode
		logger.Warn("[ListRoleApi]角色不存在", "requestID", requestID, "roleCode", roleCode)
		return &pb.ListRoleApiResponse{
			BaseResp: &pb.BaseResponse{
				Success:   false,
				Code:      2,
				Msg:       errMsg,
				RequestId: requestID,
			},
		}, nil
	}

	total, apiList, err := s.dao.RoleListApi(requestID, req)
	if err != nil {
		errMsg := "查询绑定API权限列表失败：" + err.Error()
		logger.Error("[ListRoleApi]查询列表失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		return &pb.ListRoleApiResponse{
			BaseResp: &pb.BaseResponse{
				Success:   false,
				Code:      4,
				Msg:       errMsg,
				RequestId: requestID,
			},
		}, nil
	}
	// 6. 构造返回结果
	logger.Info("[ListRoleApi]角色绑定API权限列表查询成功", "requestID", requestID, "roleCode", roleCode, "total", total)

	return &pb.ListRoleApiResponse{
		BaseResp: &pb.BaseResponse{
			Success:   true,
			Code:      0,
			Msg:       "查询成功",
			RequestId: requestID,
		},
		Total:       total,
		ApiPermList: apiList,
	}, nil
}

// ListOperLog 操作日志列表查询
func (s *service) ListOpLog(ctx context.Context, req *pb.ListOperLogRequest) (*pb.ListOperLogResponse, error) {
	// 1. RequestID + 解析分页参数
	requestID := getRequestID(ctx)

	total, resp, err := s.dao.opLogList(requestID, req)
	if err != nil && err != gorm.ErrRecordNotFound {
		errMsg := "查询操作日志列表失败：" + err.Error()
		logger.Error("[ListOperLog]查询列表失败", "requestID", requestID, "err", err)
		return &pb.ListOperLogResponse{
			BaseResp: &pb.BaseResponse{
				Success:   false,
				Code:      4,
				Msg:       errMsg,
				RequestId: requestID,
			},
		}, nil
	}

	// 5. 构造返回结果
	logger.Info("[ListOperLog]操作日志列表查询成功", "requestID", requestID, "total", total)

	return &pb.ListOperLogResponse{
		BaseResp: &pb.BaseResponse{
			Success:   true,
			Code:      0,
			Msg:       "查询成功",
			RequestId: requestID,
		},
		Total:   total,
		LogList: resp,
	}, nil
}

// CheckDevicePerm 设备权限校验（高频接口，缓存优先 + 查库回写）
func (s *service) CheckDevicePerm(ctx context.Context, req *pb.CheckDevicePermRequest) (*pb.CheckDevicePermResponse, error) {
	// 1. 核心参数：RequestID获取 + 严格参数校验
	requestID := getRequestID(ctx)
	if req.UserId == "" || req.DeviceId == "" || req.RequirePerm == pb.DevicePermType_DEVICE_PERM_UNKNOWN {
		errMsg := "参数错误：用户ID/设备ID/权限类型不能为空"
		logger.Warn("[CheckDevicePerm]参数校验失败",
			"requestID", requestID,
			"userId", req.UserId,
			"deviceId", req.DeviceId,
			"err", errMsg)
		return &pb.CheckDevicePermResponse{
			BaseResp: &pb.BaseResponse{
				Success:   false,
				Code:      1, // 参数错误码
				Msg:       errMsg,
				RequestId: requestID,
			},
			HasPerm:     false,
			CurrentPerm: pb.DevicePermType_DEVICE_PERM_UNKNOWN,
		}, nil
	}
	userID := req.UserId
	deviceID := req.DeviceId
	requiredPerm := req.RequirePerm

	// 2. 缓存优先：优先从Redis获取用户-设备权限（核心性能优化点）
	//TODO: 权限的设置有问题, 一边是枚举值 一边是字符串需要一个转换函数
	actualPerm, err := s.ch.GetUserDevicePerm(userID, deviceID)
	if err == nil && actualPerm != "" {
		// 缓存命中：判断是否拥有所需权限（OWNER拥有所有权限）
		hasPerm := actualPerm == requiredPerm || actualPerm == pb.DevicePermType_DEVICE_PERM_OWNER
		logger.Info("[CheckDevicePerm]缓存命中，权限校验完成",
			"requestID", requestID,
			"userId", userID,
			"deviceId", deviceID,
			"requiredPerm", requiredPerm,
			"actualPerm", actualPerm,
			"hasPerm", hasPerm)
		return &pb.CheckDevicePermResponse{
			BaseResp: &pb.BaseResponse{
				Success:   true,
				Code:      0, // 成功码
				Msg:       "权限校验成功",
				RequestId: requestID,
			},
			HasPerm:     hasPerm,
			CurrentPerm: actualPerm,
		}, nil
	}

	// 3. 缓存未命中/失效：查询数据库获取用户-设备实际权限
	var permModel model.PermissionIotDeviceUser
	dbErr := s.devicePermDAO.(*dao.DevicePermDAOImpl).db.WithContext(ctx).
		Where("user_id = ? AND device_id = ? AND deleted_at IS NULL", userID, deviceID).
		First(&permModel).Error

	// 4. 处理DB查询结果
	var actualPermDB string
	var hasPermDB bool
	switch {
	// 4.1 DB查询异常（如数据库连接失败）
	case dbErr != nil && dbErr != gorm.ErrRecordNotFound:
		errMsg := fmt.Sprintf("查询用户-设备权限失败：%v", dbErr)
		logger.Error("[CheckDevicePerm]DB查询异常",
			"requestID", requestID,
			"userId", userID,
			"deviceId", deviceID,
			"err", errMsg)
		return &pb.CheckDevicePermResponse{
			Base: &pb.BaseResponse{
				Success:   false,
				Code:      4, // 数据库错误码
				Msg:       errMsg,
				RequestId: requestID,
			},
			HasPerm:  false,
			PermType: "",
		}, nil

	// 4.2 DB无记录（用户未绑定该设备，无任何权限）
	case dbErr == gorm.ErrRecordNotFound:
		actualPermDB = ""
		hasPermDB = false
		logger.Warn("[CheckDevicePerm]DB无记录，用户无设备权限",
			"requestID", requestID,
			"userId", userID,
			"deviceId", deviceID)

	// 4.3 DB有记录（用户绑定了设备，判断权限是否匹配）
	default:
		actualPermDB = permModel.PermType // 数据库中存储的权限类型（OWNER/VIEW/COMMAND）
		// OWNER拥有所有权限，其他类型需严格匹配
		hasPermDB = actualPermDB == requiredPerm || actualPermDB == PermTypeOwner
		logger.Info("[CheckDevicePerm]DB查询成功，获取用户设备权限",
			"requestID", requestID,
			"userId", userID,
			"deviceId", deviceID,
			"actualPermDB", actualPermDB,
			"requiredPerm", requiredPerm,
			"hasPermDB", hasPermDB)
	}

	// 5. 缓存回写：无论是否有权限，都写入缓存（避免缓存穿透）
	// 注意：无权限时写入空字符串，设置相同过期时间，防止恶意请求打满数据库
	if err := s.cacheService.SetEx(ctx, cacheKey, actualPermDB, devicePermCacheExpire); err != nil {
		logger.Warn("[CheckDevicePerm]缓存回写失败（不影响业务）",
			"requestID", requestID,
			"cacheKey", cacheKey,
			"err", err)
	}

	// 6. 返回最终校验结果
	return &pb.CheckDevicePermResponse{
		Base: &pb.BaseResponse{
			Success:   true,
			Code:      0,
			Msg:       "权限校验成功",
			RequestId: requestID,
		},
		HasPerm:  hasPermDB,
		PermType: actualPermDB,
	}, nil
}
