package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/boqrs/iot-user-perm/pkg/model"
	pb "github.com/boqrs/iot-user-perm/pkg/proto"
	logger "github.com/boqrs/zeus/log"
	"gorm.io/gorm"
)

type daoService struct {
	db *gorm.DB
	l  logger.Logger
}

func newdaoService(sql *gorm.DB, l logger.Logger) *daoService {
	s := &daoService{
		db: sql,
		l:  l.WithField("daoService", "dao")}

	return s
}

// ========== 1. 绑定设备（创建OWNER权限） ==========
func (s *daoService) CreateDeviceOwner(deviceID, userID string) error {

	// 1. 检查设备是否已存在OWNER
	var existOwner model.PermissionIotDeviceOwner
	err := s.db.Model(&model.PermissionIotDeviceOwner{}).Where("device_id = ? AND deleted_at IS NULL", deviceID).First(&existOwner).Error
	if err == nil {
		return errors.New("device has owner")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to find device owner: %w", err)
	}

	if err = s.db.Transaction(func(tx *gorm.DB) error {
		owner := &model.PermissionIotDeviceOwner{
			DeviceID:    deviceID,
			OwnerUserID: userID,
		}

		// 2. 创建设备OWNER记录
		if err = tx.Create(owner).Error; err != nil {
			return fmt.Errorf("failed to create device owner record: %w", err)
		}

		// 3. 创建设备-用户权限绑定记录（OWNER）
		perm := &model.PermissionIotDeviceUser{
			DeviceID: deviceID,
			UserID:   userID,
			PermType: "PERMISSION_TYPE_OWNER",
		}
		if err = tx.Create(perm).Error; err != nil {
			return fmt.Errorf("failed to create OWNER permission binding record: %w", err)
		}

		return nil
	}); err != nil {
		s.l.Errorf("Transaction failed, error: %s", err.Error())
	}

	return nil
}

// ========== 2. 解绑设备（删除OWNER权限及该设备所有授权） ==========
func (s *daoService) DeleteDeviceOwner(deviceID, userID string) error {
	// 1. 校验用户是否是设备OWNER
	var owner model.PermissionIotDeviceOwner
	err := s.db.Model(&model.PermissionIotDeviceOwner{}).Where("device_id = ? AND owner_user_id = ? AND deleted_at IS NULL", deviceID, userID).First(&owner).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("the user is not the device owner and cannot unbind")
		}
		return fmt.Errorf("device owner validation failed: %w", err)
	}

	if err = s.db.Transaction(func(tx *gorm.DB) error {
		// 2. 删除设备OWNER记录（逻辑删除）
		if err = tx.Delete(&owner).Error; err != nil {
			return fmt.Errorf("failed to delete device owner record: %w", err)
		}
		// 3. 删除该设备下所有用户的权限绑定记录（逻辑删除）
		if err = tx.Where("device_id = ?", deviceID).Delete(&model.PermissionIotDeviceUser{}).Error; err != nil {
			return fmt.Errorf("failed to delete all device permission binding records: %w", err)
		}
		return nil
	}); err != nil {
		s.l.Errorf("Transaction failed, error: %s", err.Error())
		return err
	}

	return nil
}

// ========== 3. 授权其他用户设备权限（VIEW/COMMAND） ==========
func (s *daoService) CreateAuthorizedPerm(ownerUserID, authorizedUserID, deviceID, permType string) error {
	// 1. 校验授权方是设备OWNER
	var owner model.PermissionIotDeviceOwner
	err := s.db.Model(&model.PermissionIotDeviceOwner{}).Where("device_id = ? AND owner_user_id = ? AND deleted_at IS NULL", deviceID, ownerUserID).First(&owner).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("the authorizing party is not the device owner and cannot grant permissions")
		}
		return fmt.Errorf("failed to validate the authorizing party's permissions: %w", err)
	}

	// 2. 校验权限类型合法性
	validPermTypes := map[string]bool{
		"PERMISSION_TYPE_VIEW":    true,
		"PERMISSION_TYPE_COMMAND": true,
	}
	if !validPermTypes[permType] {
		return errors.New("only VIEW/COMMAND type permissions are supported for authorization")
	}

	// 3. 校验被授权方是否已存在该权限
	var existPerm model.PermissionIotDeviceUser
	err = s.db.Model(&model.PermissionIotDeviceUser{}).
		Where("device_id = ? AND user_id = ? AND perm_type = ? AND deleted_at IS NULL", deviceID, authorizedUserID, permType).
		First(&existPerm).Error
	if err == nil {
		return errors.New("the grantee already has this permission and does not need to be re-authorized")
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to validate the grantee's permissions: %w", err)
	}

	// 4. 创建授权记录
	perm := &model.PermissionIotDeviceUser{
		DeviceID: deviceID,
		UserID:   authorizedUserID,
		PermType: permType,
	}
	if err = s.db.Model(&model.PermissionIotDeviceUser{}).Create(perm).Error; err != nil {
		return fmt.Errorf("authorization failed to verify the grantee's permissions: %w", err)
	}

	return nil
}

// ========== 4. 撤销其他用户设备权限（VIEW/COMMAND） ==========
func (s *daoService) DeleteAuthorizedPerm(ownerUserID, authorizedUserID, deviceID, permType string) error {

	// 1. 校验授权方是设备OWNER
	var owner model.PermissionIotDeviceOwner
	err := s.db.Model(&model.PermissionIotDeviceOwner{}).
		Where("device_id = ? AND owner_user_id = ? AND deleted_at IS NULL", deviceID, ownerUserID).
		First(&owner).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("the authorizing party is not the device owner and cannot grant permissions")
		}
		return fmt.Errorf("failed to validate the authorizing party's permissions: %w", err)
	}

	// 2. 校验被授权方存在该权限
	var perm model.PermissionIotDeviceUser
	err = s.db.Model(&model.PermissionIotDeviceUser{}).
		Where("device_id = ? AND user_id = ? AND perm_type = ? AND deleted_at IS NULL", deviceID, authorizedUserID, permType).
		First(&perm).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("the grantee does not have this permission, so revocation is not required")
		}
		return fmt.Errorf("failed to validate the grantee's permissions: %w", err)
	}

	// 3. 删除授权记录（逻辑删除）
	if err = s.db.Model(&model.PermissionIotDeviceUser{}).Delete(&perm).Error; err != nil {
		return fmt.Errorf("删除授权权限记录失败: %w", err)
	}

	return nil
}

// ========== 5. 查询用户对设备的权限 ==========
func (s *daoService) GetUserDevicePerm(userID, deviceID string) (string, error) {
	var perm model.PermissionIotDeviceUser
	err := s.db.Model(&model.PermissionIotDeviceUser{}).
		Where("user_id = ? AND device_id = ? AND deleted_at IS NULL", userID, deviceID).
		First(&perm).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "PERMISSION_TYPE_UNKNOWN", nil // 无权限
		}
		return "", fmt.Errorf("failed to find user perm: %w", err)
	}
	return perm.PermType, nil
}

// ========== 6. 查询设备的所有权限用户（按类型分类） ==========
func (s *daoService) GetDeviceAllPermUsers(deviceID string) (map[string][]string, error) {
	var perms []model.PermissionIotDeviceUser
	err := s.db.Model(&model.PermissionIotDeviceUser{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		Find(&perms).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find device all users: %w", err)
	}

	// 按权限类型分组
	permUsers := make(map[string][]string)
	for _, perm := range perms {
		permUsers[perm.PermType] = append(permUsers[perm.PermType], perm.UserID)
	}

	return permUsers, nil
}

// ========== 7. 查询设备的OWNER用户ID ==========
func (s *daoService) GetDeviceOwner(deviceID string) (string, error) {
	var owner model.PermissionIotDeviceOwner
	err := s.db.Model(&model.PermissionIotDeviceOwner{}).
		Where("device_id = ? AND deleted_at IS NULL", deviceID).
		First(&owner).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", errors.New("device has no owner")
		}
		return "", fmt.Errorf("failed to find device owner: %w", err)
	}
	return owner.OwnerUserID, nil
}

// ========== 8. 查询设备的所有授权用户（VIEW/COMMAND） ==========
func (s *daoService) GetAuthorizedUsers(deviceID string) ([]string, error) {
	var perms []model.PermissionIotDeviceUser
	err := s.db.Model(&model.PermissionIotDeviceUser{}).
		Where("device_id = ? AND perm_type IN (?, ?) AND deleted_at IS NULL", deviceID, "PERMISSION_TYPE_VIEW", "PERMISSION_TYPE_COMMAND").
		Find(&perms).Error
	if err != nil {
		return nil, fmt.Errorf("failed to find device all auth users: %w", err)
	}

	userIDs := make([]string, 0, len(perms))
	for _, perm := range perms {
		userIDs = append(userIDs, perm.UserID)
	}
	return userIDs, nil
}

// ========== 9. 批量删除设备所有权限（设备注销） ==========
func (s *daoService) BatchDeleteDevicePerm(deviceID string) error {

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		// 1. 删除设备OWNER记录
		if err := tx.Where("device_id = ?", deviceID).Delete(&model.PermissionIotDeviceOwner{}).Error; err != nil {
			return fmt.Errorf("failed to delete device ownner: %w", err)
		}

		// 2. 删除设备所有权限绑定记录
		if err := tx.Where("device_id = ?", deviceID).Delete(&model.PermissionIotDeviceUser{}).Error; err != nil {
			return fmt.Errorf("failed to delete device all users: %w", err)
		}
		return nil
	}); err != nil {
		s.l.Errorf("Transaction failed, error: %s", err.Error())
	}

	return nil
}

func (d *daoService) GetUserDeviceList(userID string, filterPermTypes []string, offset, limit int) ([]*UserDeviceItem, int64, error) {
	if userID == "" {
		return nil, 0, errors.New("user_id不能为空")
	}

	// 构建查询
	db := d.db.Model(&model.PermissionIotDeviceUser{}).
		Select("device_id, perm_type").
		Where("user_id = ?", userID)

	// 筛选权限类型
	if len(filterPermTypes) > 0 {
		db = db.Where("perm_type IN (?)", filterPermTypes)
	}

	// 查询总数量
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to query total count: %w", err)
	}

	// 分页查询数据
	var items []*UserDeviceItem
	if err := db.Offset(offset).Limit(limit).Find(&items).Error; err != nil {
		return nil, 0, fmt.Errorf("分页查询设备列表失败: %w", err)
	}

	return items, total, nil
}

func (d *daoService) BatchGetDevicePerms(deviceIDs []string, userID string) (map[string][]*DevicePermUserItem, error) {
	if len(deviceIDs) == 0 {
		return nil, errors.New("device IDs cannot be empty")
	}

	// 构建查询
	db := d.db.Model(&model.PermissionIotDeviceUser{}).
		Select("device_id, user_id, perm_type").
		Where("device_id IN (?)", deviceIDs)

	// 指定用户时，筛选该用户
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}

	// 查询数据
	//var items []*DevicePermUserItem
	// 这里需要手动关联device_id，因为GORM查询结果不包含device_id在结构体中，需调整结构体或查询
	// 修正：重新定义临时结构体接收数据
	type tempItem struct {
		DeviceID string `gorm:"column:device_id"`
		UserID   string `gorm:"column:user_id"`
		PermType string `gorm:"column:perm_type"`
	}
	var tempItems []tempItem
	if err := db.Find(&tempItems).Error; err != nil {
		return nil, fmt.Errorf("批量查询设备权限失败: %w", err)
	}

	// 转换为map：device_id → []DevicePermUserItem
	result := make(map[string][]*DevicePermUserItem)
	for _, item := range tempItems {
		if _, ok := result[item.DeviceID]; !ok {
			result[item.DeviceID] = make([]*DevicePermUserItem, 0)
		}
		result[item.DeviceID] = append(result[item.DeviceID], &DevicePermUserItem{
			UserID:   item.UserID,
			PermType: item.PermType,
		})
	}

	return result, nil
}

func (s *daoService) CheckPermIDExist(permID string) (bool, error) {
	if permID == "" {
		return false, errors.New("权限ID不能为空")
	}

	var count int64
	err := s.db.Model(&model.PermissionApi{}).
		Where("perm_id = ?", permID).
		Count(&count).Error

	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *daoService) CreateApiPerm(data *model.PermissionApi) error {
	if data == nil {
		return errors.New("param error")
	}

	if err := s.db.Model(&model.PermissionApi{}).Create(data).Error; err != nil {
		return err
	}
	return nil
}

func (s daoService) CheckRoleCodeExist(roleCode string) (bool, error) {
	var count int64
	if err := s.db.Model(&model.PermissionRole{}).Where("RoleCode = ?", roleCode).Count(&count).Error; err != nil {
		return false, err
	}

	return count != 0, nil
}

func (s daoService) CreateRole(role *model.PermissionRole) error {
	if err := s.db.Model(&model.PermissionRole{}).Create(role).Error; err != nil {
		return err
	}

	return nil
}

func (r *daoService) CheckRoleApiExist(roleCode, permID string) (bool, error) {
	var count int64
	err := r.db.Model(&model.PermissionRoleApi{}).
		Where("role_code = ? AND perm_id = ? AND deleted_at IS NULL", roleCode, permID).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *daoService) BatchCreateRoleApi(roleApis []*model.PermissionRoleApi) error {

	return r.db.CreateInBatches(roleApis, len(roleApis)).Error
}

func (r *daoService) UpdatePermissionApi(updateData map[string]interface{}) error {

	return r.db.Model(&model.PermissionApi{}).Updates(updateData).Error
}

func (r *daoService) GetPermissionApi(permID string) (*model.PermissionApi, error) {
	var latestApiPerm model.PermissionApi
	if err := r.db.Model(&model.PermissionApi{}).
		Where("perm_id = ? AND deleted_at IS NULL", permID).
		First(&latestApiPerm).Error; err != nil {
		logger.Warn("[UpdateApiPerm]查询最新数据失败，缓存未更新", "requestID", "permID", permID, "err", err)
		return nil, err
	}
	return &latestApiPerm, nil
}

func (r *daoService) DeletePermissionApi(permID string) error {
	return r.db.Model(&model.PermissionApi{}).Where("perm_id = ? AND deleted_at IS NULL", permID).
		Delete(&model.PermissionApi{}).Error
}

func (r *daoService) PermissionApiList(requestID string, req *pb.ListApiPermRequest) (int64, []*model.PermissionApi, error) {
	page, size := ParsePageParam(req.Page)
	offset := (page - 1) * size

	// 2. 构造查询条件
	db := r.db.Model(&model.PermissionApi{}).Where("deleted_at IS NULL")
	// 模糊搜索（名称/PermID）
	if req.Page != nil && req.Page.Keyword != "" {
		keyword := "%" + strings.TrimSpace(req.Page.Keyword) + "%"
		db = db.Where("perm_id LIKE ? OR perm_name LIKE ?", keyword, keyword)
	}

	// 3. 查询总条数
	var apiPermList []*model.PermissionApi
	var total int64
	if err := db.Count(&total).Error; err != nil {
		logger.Errorf("[ListApiPerm]查询总条数失败 requestID: %s, error: %s", requestID, err)
		return 0, apiPermList, nil
	}

	// 4. 分页查询列表数据
	if total > 0 {
		err := db.Order("created_at DESC").Limit(int(size)).Offset(int(offset)).Find(&apiPermList).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			logger.Error("[ListApiPerm]查询列表失败requestID: %s, error: %s", requestID, err)
			return 0, apiPermList, nil
		}
	}
	return total, apiPermList, nil
}

func (r *daoService) UpdatePermRole(update map[string]interface{}) error {
	return r.db.Model(&model.PermissionRole{}).Updates(update).Error
}

func (r *daoService) GetPermRole(roleCode string) (*model.PermissionRole, error) {
	var data model.PermissionRole

	if err := r.db.Model(&model.PermissionRole{}).Where("role_code = ?", roleCode).First(&data).Error; err != nil {
		return nil, err
	}

	return &data, nil
}

func (r *daoService) DelPermRole(roleCode string) error {
	return r.db.Model(&model.PermissionRole{}).Where("role_code = ? AND deleted_at IS NULL", roleCode).Delete(&model.PermissionRole{})
}

func (r *daoService) ListRole(requestID string, req *pb.ListRoleRequest) (int64, []*pb.RoleInfo, error) {
	page, size := ParsePageParam(req.Page)
	offset := (page - 1) * size

	// 2. 构造查询条件
	db := r.db.Model(&model.PermissionRole{}).Where("deleted_at IS NULL")
	// 模糊搜索（角色名称/编码）
	if req.Page != nil && req.Page.Keyword != "" {
		keyword := "%" + strings.TrimSpace(req.Page.Keyword) + "%"
		db = db.Where("role_code LIKE ? OR role_name LIKE ?", keyword, keyword)
	}

	// 3. 查询总条数
	var total int64
	resp := make([]*pb.RoleInfo, 0)
	var roleList []*model.PermissionRole
	if err := db.Count(&total).Error; err != nil {
		logger.Error("[ListRole]查询总条数失败", "requestID", requestID, "err", err)
		return 0, resp, err
	}

	// 4. 分页查询列表
	if total > 0 {
		err := db.Order("created_at DESC").Limit(int(size)).Offset(int(offset)).Find(&roleList).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			logger.Error("[ListRole]查询列表失败", "requestID", requestID, "err", err)
			return 0, resp, err
		}
	}

	for _, role := range roleList {
		resp = append(resp, &pb.RoleInfo{
			Remark:   role.Remark,
			RoleCode: role.RoleCode,
			RoleName: role.RoleName,
		})
	}

	return total, resp, nil
}

func (r *daoService) DelPermRoleApi(roleCode string, permIDs []string) error {
	return r.db.Model(&model.PermissionRoleApi{}).Where("role_code = ? AND perm_id IN (?) AND deleted_at IS NULL", roleCode, permIDs).
		Delete(&model.PermissionRoleApi{}).Error
}

func (r *daoService) RoleListApi(requestID string, req *pb.ListRoleApiRequest) (int64, []*pb.ApiPermInfo, error) {
	page, size := ParsePageParam(req.Page)
	offset := (page - 1) * size

	// 3. 构造关联查询条件：角色-API绑定表关联API权限表，查询未软删除的记录
	db := r.db.
		Model(&model.PermissionRoleApi{}).
		Where("permission_role_api.role_code = ? AND permission_role_api.deleted_at IS NULL", roleCode).
		Joins("LEFT JOIN permission_apis ON permission_role_api.perm_id = permission_apis.perm_id AND permission_apis.deleted_at IS NULL").
		Select("permission_apis.*")

	resp := make([]*pb.ApiPermInfo, 0)
	// 4. 查询总条数
	var total int64
	if err := db.Count(&total).Error; err != nil {
		logger.Error("[ListRoleApi]查询总条数失败", "requestID", requestID, "roleCode", roleCode, "err", err)
		return 0, resp, nil
	}

	// 5. 分页查询列表
	var apiPermList []*model.PermissionApi
	if total > 0 {
		err := db.Order("permission_apis.created_at DESC").Limit(int(size)).Offset(int(offset)).Find(&apiPermList).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			logger.Error("[ListRoleApi]查询列表失败", "requestID", requestID, "roleCode", roleCode, "err", err)
			return 0, nil, nil
		}
	}

	return total, resp, nil
}

func (s *daoService) opLogList(requestID string, req *pb.ListOperLogRequest) (int64, []*pb.OperLogItem, error) {
	page, size := ParsePageParam(req.Page)
	offset := (page - 1) * size

	// 2. 构造查询条件
	db := s.db.Model(&model.PermissionOperationLog{})
	// 按操作人ID筛选
	if req.OperatorId != "" {
		db = db.Where("operator_id = ?", req.OperatorId)
	}
	// 按操作类型筛选
	if req.OperType != pb.OperType_OPER_TYPE_UNKNOWN {
		db = db.Where("oper_type = ?", req.OperType)
	}
	// 按时间范围筛选（yyyy-MM-dd HH:mm:ss）
	if req.StartTime != "" {
		startTime, err := time.Parse("2006-01-02 15:04:05", req.StartTime)
		if err == nil {
			db = db.Where("created_at >= ?", startTime)
		}
	}
	if req.EndTime != "" {
		endTime, err := time.Parse("2006-01-02 15:04:05", req.EndTime)
		if err == nil {
			db = db.Where("created_at <= ?", endTime)
		}
	}

	// 3. 查询总条数（日志为物理存储，无软删除）
	var total int64
	var resp = make([]*pb.OperLogItem, 0)
	if err := db.Count(&total).Error; err != nil {
		logger.Error("[ListOperLog]查询总条数失败", "requestID", requestID, "err", err)
		return 0, resp, nil
	}

	// 4. 分页查询列表（按创建时间倒序，最新日志在前）
	var operLogList []*model.PermissionOperationLog
	if total > 0 {
		err := db.Order("created_at DESC").Limit(int(size)).Offset(int(offset)).Find(&operLogList).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			logger.Error("[ListOperLog]查询列表失败", "requestID", requestID, "err", err)
			return 0, resp, nil
		}
	}

	return total, resp, nil
}

// TODO：后续决定什么地方需要加日志
func (s *daoService) recordOperLog(requestID string, req interface{}, result pb.OperResult, errMsg string) {
	// 异步执行
	go func() {
		// 序列化请求参数为JSON（操作内容）
		reqJson, err := json.Marshal(req)
		if err != nil {
			reqJson = []byte("请求参数序列化失败")
			logger.Warn("[recordOperLog]参数序列化失败", "requestID", requestID, "err", err)
		}
		// 构造日志Model（根据不同req类型解析操作人/操作名称，此处简化为通用解析）
		logModel := &model.PermissionOperationLog{
			LogID:        requestID,
			OperatorID:   getOperatorID(req),        // 辅助方法：从req中解析操作人ID
			OperatorName: getOperatorName(req),      // 辅助方法：从req中解析操作人名称
			OperType:     getOperType(req).String(), // 辅助方法：从req中解析操作类型
			OperContent:  string(reqJson),
			OperIP:       getOperIP(req), // 辅助方法：从req中解析操作IP
			OperResult:   result.String(),
			ErrorMsg:     errMsg,
		}
		// 写入数据库
		if err = s.db.Model(&model.PermissionOperationLog{}).Create(logModel).Error; err != nil {
			logger.Error("[recordOperLog]日志写入失败", "requestID", requestID, "err", err)
		}
	}()
}
