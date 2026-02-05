package rpc

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/boqrs/comm/database/cache"
	"github.com/boqrs/iot-user-perm/config"
	"github.com/boqrs/iot-user-perm/pkg/model"
	logger "github.com/boqrs/zeus/log"
	"gorm.io/gorm"
)

type daoService struct {
	db    *gorm.DB
	cache cache.Cache
	cfg   *config.Config
	l     logger.Logger
}

func newdaoService(sql *gorm.DB, cfg *config.Config, ch cache.Cache, l logger.Logger) *daoService {
	s := &daoService{
		db:    sql,
		cfg:   cfg,
		cache: ch,
		l:     l.WithField("daoServices", "rpc_dao")}

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

const (
	// 单用户-单设备权限缓存 Key: iot:device:perm:{userID}:{deviceID}
	KeyUserDevicePerm = "iot:device:perm:%s:%s"
	// 设备OWNER缓存 Key: iot:device:owners:{deviceID}
	KeyDeviceOwner = "iot:device:owners:%s"
	// 用户设备列表缓存（Set） Key: iot:user:devices:{userID}
	KeyUserDevices = "iot:user:devices:%s"
	// 设备权限用户Hash缓存 Key: iot:device:perm_users:{deviceID}
	KeyDevicePermUsersHash = "iot:device:perm_users:%s"
	// 设备权限用户Set缓存 Key: iot:device:perm_users_all:{deviceID}
	KeyDevicePermUsersSet = "iot:device:perm_users_all:%s"
)

func (s *daoService) SetUserDevicePermCache(userID, deviceID, permType string) error {
	key := fmt.Sprintf(KeyUserDevicePerm, userID, deviceID)
	return s.cache.Set(key, permType, 0) // 0=永久有效
}

// ========== 2. 获取单用户-单设备权限缓存 ==========
func (s *daoService) GetUserDevicePermCache(userID, deviceID string) (string, error) {
	key := fmt.Sprintf(KeyUserDevicePerm, userID, deviceID)
	return s.cache.Get(key)
}

// ========== 3. 删除单用户-单设备权限缓存 ==========
func (s *daoService) DelUserDevicePermCache(userID, deviceID string) error {
	key := fmt.Sprintf(KeyUserDevicePerm, userID, deviceID)
	return s.cache.Del(key)
}

// ========== 4. 刷新缓存为永久有效 ==========
func (s *daoService) RefreshPermCache(keys ...string) error {
	pipe := s.cache.Pipeline()
	for _, key := range keys {
		pipe.Expire(key, 0) // 0=永久有效
	}
	_, err := pipe.Exec()
	return err
}

// ========== 5. 设置设备OWNER缓存（永久有效） ==========
func (s *daoService) SetDeviceOwnerCache(deviceID, userID string) error {
	key := fmt.Sprintf(KeyDeviceOwner, deviceID)
	return s.cache.Set(key, userID, 0)
}

// ========== 6. 删除设备OWNER缓存 ==========
func (s *daoService) DelDeviceOwnerCache(deviceID string) error {
	key := fmt.Sprintf(KeyDeviceOwner, deviceID)
	return s.cache.Del(key)
}

// ========== 7. 添加用户设备列表缓存（Set，永久有效） ==========
func (s *daoService) SAddUserDevicesCache(userID string, deviceIDs ...string) error {
	key := fmt.Sprintf(KeyUserDevices, userID)
	return s.cache.SAdd(key, deviceIDs...)
}

// ========== 8. 移除用户设备列表缓存（Set） ==========
func (s *daoService) SRemUserDevicesCache(userID string, deviceIDs ...string) error {
	key := fmt.Sprintf(KeyUserDevices, userID)
	return s.cache.SRem(key, deviceIDs...)
}

// ========== 9. 删除空的用户设备列表缓存 ==========
func (s *daoService) DelEmptyUserDevicesCache(userID string) error {
	key := fmt.Sprintf(KeyUserDevices, userID)
	card, err := s.cache.SCard(key)
	if err != nil {
		return err
	}
	if card == 0 {
		return s.cache.Del(key)
	}
	return nil
}

// ========== 10. 更新设备权限用户缓存（Hash+Set，永久有效） ==========
func (s *daoService) UpdateDevicePermUsersCache(deviceID string, permUsers map[string][]string) error {
	hashKey := fmt.Sprintf(KeyDevicePermUsersHash, deviceID)
	setKey := fmt.Sprintf(KeyDevicePermUsersSet, deviceID)

	pipe := s.cache.Pipeline()
	// 清空旧缓存
	pipe.Del(hashKey, setKey)

	// 组装Hash和Set数据
	allUserIDs := make([]string, 0)
	for permType, userIDs := range permUsers {
		if len(userIDs) == 0 {
			continue
		}
		// Hash: permType -> userID1,userID2
		pipe.HSet(hashKey, permType, strings.Join(userIDs, ","))
		// Set: 所有用户ID
		allUserIDs = append(allUserIDs, userIDs...)
	}

	// 写入Set
	if len(allUserIDs) > 0 {
		pipe.SAdd(setKey, allUserIDs)
	}

	// 执行管道操作（无过期，永久有效）
	_, err := pipe.Exec()
	return err
}

// ========== 11. 获取设备所有权限用户（Set） ==========
func (s *daoService) GetDevicePermUsersSetCache(deviceID string) ([]string, error) {
	key := fmt.Sprintf(KeyDevicePermUsersSet, deviceID)
	return s.cache.SMembers(key)
}

// ========== 12. 获取设备权限用户（Hash） ==========
func (s *daoService) GetDevicePermUsersHashCache(deviceID string) (map[string]string, error) {
	key := fmt.Sprintf(KeyDevicePermUsersHash, deviceID)
	return s.cache.HGetAll(key)
}

// ========== 13. 批量删除设备所有权限缓存 ==========
func (s *daoService) BatchDelDevicePermCache(deviceID string) error {
	// 1. 删除设备OWNER缓存
	_ = s.DelDeviceOwnerCache(deviceID)

	// 2. 删除设备权限用户Hash/Set缓存
	hashKey := fmt.Sprintf(KeyDevicePermUsersHash, deviceID)
	setKey := fmt.Sprintf(KeyDevicePermUsersSet, deviceID)
	_ = s.cache.Del(hashKey, setKey)

	// 3. 模糊删除该设备的所有用户权限缓存（SCAN避免KEYS阻塞）
	iter := s.cache.Scan(0, fmt.Sprintf(KeyUserDevicePerm, "*", deviceID), 100)
	for iter.Next() {
		_ = s.cache.Del(iter.Val())
	}

	return iter.Err()
}

func (s *daoService) SMembersUserDevicesCache(userID string) ([]string, error) {
	if userID == "" {
		return nil, fmt.Errorf("user_id should not be null")
	}
	key := fmt.Sprintf(KeyUserDevices, userID)
	return s.cache.SMembers(key)
}

func (s *daoService) HSetDevicePermsCache(deviceID string, userPermMap map[string]interface{}) error {
	if deviceID == "" || len(userPermMap) == 0 {
		return nil
	}
	key := fmt.Sprintf(KeyUserDevices, deviceID)
	return s.cache.HMSet(key, userPermMap)
}

func (c *daoService) HGetDevicePerms(deviceID string) (map[string]string, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("device_id should not be empty")
	}
	key := fmt.Sprintf(KeyDevicePermUsersHash, deviceID)
	return c.cache.HGetAll(key)
}
func (s *daoService) RefreshCache(key string) error {
	return s.cache.Expire(key, time.Hour*24) //TODO：need fix
}
