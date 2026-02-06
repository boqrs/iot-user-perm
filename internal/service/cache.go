package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/boqrs/comm/database/cache"
	logger "github.com/boqrs/zeus/log"
)

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
	KeyApiPerm            = "iot:api:perm:%s"
	KeyPermRole           = "iot:role:%s"
	KeyPermRoleApis       = "iot:role:apis:%s"
)

type cacheService struct {
	log   logger.Logger
	cache cache.Cache
}

func NewCacheService(ch cache.Cache, l logger.Logger) *cacheService {
	return &cacheService{
		log:   l,
		cache: ch,
	}
}

func (s *cacheService) SetUserDevicePermCache(userID, deviceID, permType string) error {
	key := fmt.Sprintf(KeyUserDevicePerm, userID, deviceID)
	return s.cache.Set(key, permType, 0) // 0=永久有效
}

// ========== 2. 获取单用户-单设备权限缓存 ==========
func (s *cacheService) GetUserDevicePermCache(userID, deviceID string) (string, error) {
	key := fmt.Sprintf(KeyUserDevicePerm, userID, deviceID)
	return s.cache.Get(key)
}

// ========== 3. 删除单用户-单设备权限缓存 ==========
func (s *cacheService) DelUserDevicePermCache(userID, deviceID string) error {
	key := fmt.Sprintf(KeyUserDevicePerm, userID, deviceID)
	return s.cache.Del(key)
}

// ========== 4. 刷新缓存为永久有效 ==========
func (s *cacheService) RefreshPermCache(keys ...string) error {
	pipe := s.cache.Pipeline()
	for _, key := range keys {
		pipe.Expire(key, 0) // 0=永久有效
	}
	_, err := pipe.Exec()
	return err
}

// ========== 5. 设置设备OWNER缓存（永久有效） ==========
func (s *cacheService) SetDeviceOwnerCache(deviceID, userID string) error {
	key := fmt.Sprintf(KeyDeviceOwner, deviceID)
	return s.cache.Set(key, userID, 0)
}

// ========== 6. 删除设备OWNER缓存 ==========
func (s *cacheService) DelDeviceOwnerCache(deviceID string) error {
	key := fmt.Sprintf(KeyDeviceOwner, deviceID)
	return s.cache.Del(key)
}

// ========== 7. 添加用户设备列表缓存（Set，永久有效） ==========
func (s *cacheService) SAddUserDevicesCache(userID string, deviceIDs ...string) error {
	key := fmt.Sprintf(KeyUserDevices, userID)
	return s.cache.SAdd(key, deviceIDs...)
}

// ========== 8. 移除用户设备列表缓存（Set） ==========
func (s *cacheService) SRemUserDevicesCache(userID string, deviceIDs ...string) error {
	key := fmt.Sprintf(KeyUserDevices, userID)
	return s.cache.SRem(key, deviceIDs...)
}

// ========== 9. 删除空的用户设备列表缓存 ==========
func (s *cacheService) DelEmptyUserDevicesCache(userID string) error {
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
func (s *cacheService) UpdateDevicePermUsersCache(deviceID string, permUsers map[string][]string) error {
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
func (s *cacheService) GetDevicePermUsersSetCache(deviceID string) ([]string, error) {
	key := fmt.Sprintf(KeyDevicePermUsersSet, deviceID)
	return s.cache.SMembers(key)
}

// ========== 12. 获取设备权限用户（Hash） ==========
func (s *cacheService) GetDevicePermUsersHashCache(deviceID string) (map[string]string, error) {
	key := fmt.Sprintf(KeyDevicePermUsersHash, deviceID)
	return s.cache.HGetAll(key)
}

// ========== 13. 批量删除设备所有权限缓存 ==========
func (s *cacheService) BatchDelDevicePermCache(deviceID string) error {
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

func (s *cacheService) SMembersUserDevicesCache(userID string) ([]string, error) {
	if userID == "" {
		return nil, fmt.Errorf("user_id should not be null")
	}
	key := fmt.Sprintf(KeyUserDevices, userID)
	return s.cache.SMembers(key)
}

func (s *cacheService) HSetDevicePermsCache(deviceID string, userPermMap map[string]interface{}) error {
	if deviceID == "" || len(userPermMap) == 0 {
		return nil
	}
	key := fmt.Sprintf(KeyUserDevices, deviceID)
	return s.cache.HMSet(key, userPermMap)
}

func (c *cacheService) HGetDevicePerms(deviceID string) (map[string]string, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("device_id should not be empty")
	}
	key := fmt.Sprintf(KeyDevicePermUsersHash, deviceID)
	return c.cache.HGetAll(key)
}

func (s *cacheService) RefreshCache(key string) error {
	return s.cache.Expire(key, time.Hour*24) //TODO：need fix
}

func (s *cacheService) SetApiPerm(permID, Value string, ttl time.Duration) error {
	return s.cache.Set(fmt.Sprintf(KeyApiPerm, permID), Value, ttl)
}

func (c *cacheService) SetRole(roleCode string, role string) error {
	return c.cache.Set(KeyPermRole, role, -1)
}

// SAddRoleApiPerms 向【角色-API权限Set】添加权限ID（Key:iot:role:apis:{roleCode} → 成员:permID）
func (c *cacheService) SAddRoleApiPerms(roleCode string, permIDs ...string) error {
	return c.cache.SAdd(fmt.Sprintf(KeyPermRoleApis, roleCode), permIDs...)
}

func (c *cacheService) DelRoleApi(permID string) error {
	return c.cache.Del(permID)
}

func (c *cacheService) UpdateRole(roleCode string, role string) error {
	return c.cache.Set(fmt.Sprintf(KeyPermRole, roleCode), role, -1)
}

func (c *cacheService) DelRoles(keys ...string) error {
	return c.cache.Del(keys...)
}

func (c *cacheService) DelRoleApis(key string, keys ...string) error {
	return c.cache.SRem(key, keys...)
}

func (c *cacheService) GetUserDevicePerm(userID, DeviceID string) (string, error) {
	return c.cache.Get(fmt.Sprintf(KeyUserDevicePerm, userID, DeviceID))
}
