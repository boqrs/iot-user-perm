package admin

import (
	"errors"
	"fmt"
	"time"

	"github.com/boqrs/iot-user-perm/pkg/comm"
	"github.com/boqrs/iot-user-perm/pkg/errs"
	"github.com/boqrs/iot-user-perm/pkg/model"
	"github.com/boqrs/iot-user-perm/pkg/utils"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Create 创建管理员
func (s *service) Create(admin *model.PermissionAdmin) error {
	return s.db.Model(&model.PermissionAdmin{}).Create(admin).Error
}

// Delete 删除管理员（逻辑删除）
func (s *service) Delete(userID string) error {
	return s.db.Model(&model.PermissionAdmin{}).Where("user_id = ? AND role_code != ?", userID, "SUPER_ADMIN").Update("status", "DELETED").Error
}

// UpdatePassword 修改密码
func (s *service) UpdatePassword(userID, password string) error {
	return s.db.Model(&model.PermissionAdmin{}).Where("user_id = ?", userID).Update("password", password).Error
}

// UpdateFirstLogin 标记首次登录为已修改密码
func (s *service) UpdateFirstLogin(userID string) error {
	return s.db.Model(&model.PermissionAdmin{}).Where("user_id = ?", userID).Update("is_first_login", 0).Error
}

// GetByUsername 根据用户名查询
func (s *service) GetByUsername(username string) (*model.PermissionAdmin, error) {
	var admin model.PermissionAdmin
	err := s.db.Model(&model.PermissionAdmin{}).Where("username = ?", username).First(&admin).Error
	return &admin, err
}

// GetByUserID 根据用户ID查询
func (s *service) GetByUserID(userID string) (*model.PermissionAdmin, error) {
	var admin model.PermissionAdmin
	err := s.db.Model(&model.PermissionAdmin{}).Where("user_id = ?", userID).First(&admin).Error
	return &admin, err
}

// List 分页查询管理员列表（排除超管）
func (s *service) List(req *AdminListReq) (int64, []model.PermissionAdmin, error) {
	var list []model.PermissionAdmin
	var total int64

	// 构建查询条件
	query := s.db.Model(&model.PermissionAdmin{}).Where("role_code = ?", "ADMIN")
	if req.Username != "" {
		query = query.Where("username LIKE ?", "%"+req.Username+"%")
	}
	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}

	// 统计总数
	if err := query.Count(&total).Error; err != nil {
		return 0, nil, err
	}

	// 分页查询
	offset := (req.CurrentPage - 1) * req.PageSize
	if err := query.Offset(offset).Limit(req.PageSize).Find(&list).Error; err != nil {
		return 0, nil, err
	}

	return total, list, nil
}

func (s *service) logList(req *LogListReq) (*LogListResp, error) {
	q := s.db.Model(&model.PermissionOperationLog{})
	if req.OperatorID != "" {
		q = q.Where("operator_id = ?", req.OperatorID)
	}

	if req.OperType != "" {
		q = q.Where("oper_type = ?", req.OperType)
	}

	if req.StartTime != "" {
		q = q.Where("create_time >= ?", req.StartTime)

	}

	if req.EndTime != "" {
		q = q.Where("create_time <= ?", req.EndTime)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		s.l.Errorf("failed to count log, error: %s", err.Error())
		return nil, err
	}

	var detail []*model.PermissionOperationLog
	var offset = (req.CurrentPage - 1) * req.PageSize
	if err := q.Offset(offset).Limit(req.PageSize).Find(&detail).Error; err != nil {
		s.l.Errorf("failed to find logs, user: %s, req: %#v, error: %s", req, err.Error())
		return nil, errs.NewError(errs.Internal)
	}
	rp := &LogListResp{
		Detail: detail,
		PageBaseResp: comm.PageBaseResp{
			Total: total,
		},
	}

	if int64(offset+req.PageSize) < total {
		rp.Next = true
	}

	return rp, nil
}

func (s *service) RecordLoginLog(userID, userName, ip, opType, result, errMsg string) error {
	var rol = &model.PermissionOperationLog{
		OperIP:       ip,
		OperatorName: userName,
		OperatorID:   userID,
		OperType:     opType,
		OperResult:   result,
		ErrorMsg:     errMsg,
	}
	return s.db.Model(&model.PermissionOperationLog{}).Create(rol).Error
}

func (s *service) CheckUsernameExist(username string) (bool, error) {
	var count int64
	if err := s.db.Model(&model.PermissionAdmin{}).Where("username = ?", username).Count(&count).Error; err != nil {
		s.l.Errorf("failed to count user, error: %s", err.Error())
		return false, err
	}
	if count > 0 {
		return true, nil
	}

	return false, nil
}

func (s *service) CreateLog(data *model.PermissionOperationLog) error {
	return s.db.Model(&model.PermissionOperationLog{}).Create(&data).Error
}

func (s *service) CreateAdmin(req *CreateAdminReq, operatorID, operatorName, operIP string) (*model.PermissionAdmin, error) {
	// 1. 校验用户名是否存在
	opLog := &model.PermissionOperationLog{
		LogID:        uuid.NewString(),
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "create_admin",
		OperContent:  fmt.Sprintf("create admin %s", req.Username),
		OperIP:       operIP,
	}

	existAdmin, err := s.GetByUsername(req.Username)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		opLog.OperResult = "failed"
		opLog.ErrorMsg = err.Error()
		if err := s.CreateLog(opLog); err != nil {
			s.l.Errorf("failed to create log: %#v, error: %s", opLog, err.Error())
		}
		return nil, err
	}
	if existAdmin != nil {
		opLog.OperResult = "failed"
		opLog.ErrorMsg = "user already existed"
		if err := s.CreateLog(opLog); err != nil {
			s.l.Errorf("failed to create log: %#v, error: %s", opLog, err.Error())
		}
		return nil, errors.New("用户名已存在")
	}

	// 2. 校验密码复杂度
	if !utils.CheckPasswordComplexity(req.Password) {
		opLog.OperResult = "failed"
		opLog.ErrorMsg = "password formate error"
		if err := s.CreateLog(opLog); err != nil {
			s.l.Errorf("failed to create log: %#v, error: %s", opLog, err.Error())
		}
		return nil, errors.New("密码需包含大小写字母、数字、特殊字符，长度≥8")
	}

	// 3. 密码加密
	encryptPwd, err := utils.BcryptEncrypt(req.Password)
	if err != nil {
		opLog.OperResult = "failed"
		opLog.ErrorMsg = "password bcrypt error"
		if err := s.CreateLog(opLog); err != nil {
			s.l.Errorf("failed to create log: %#v, error: %s", opLog, err.Error())
		}
		return nil, err
	}

	// 4. 构建管理员数据
	admin := &model.PermissionAdmin{
		UserID:       "admin_" + uuid.NewString(),
		Username:     req.Username,
		Password:     encryptPwd,
		RoleCode:     "ADMIN",
		Status:       "ENABLED",
		IsFirstLogin: 1,
		Remark:       req.Remark,
		CreateTime:   time.Now(),
		UpdateTime:   time.Now(),
	}

	// 5. 插入数据库
	if err = s.Create(admin); err != nil {
		opLog.OperResult = "failed"
		opLog.ErrorMsg = err.Error()
		if err := s.CreateLog(opLog); err != nil {
			s.l.Errorf("failed to create log: %#v, error: %s", opLog, err.Error())
		}

		return nil, err
	}
	opLog.OperResult = "success"
	opLog.ErrorMsg = "add admin user"
	if err := s.CreateLog(opLog); err != nil {
		s.l.Errorf("failed to create log: %#v, error: %s", opLog, err.Error())
	}

	return admin, nil
}

func (d *service) CheckPermIDsExist(permIDs []string) ([]string, bool) {
	if len(permIDs) == 0 {
		return []string{}, false
	}

	// 查询数据库中存在的权限ID
	var existPermIDs []string
	err := d.db.Model(&model.PermissionRoleApi{}).
		Select("perm_id").
		Where("perm_id IN ?", permIDs).
		Find(&existPermIDs).Error

	if err != nil || len(existPermIDs) == 0 {
		return permIDs, false // 全部不存在
	}

	// 找出不存在的权限ID
	existMap := make(map[string]bool)
	for _, pid := range existPermIDs {
		existMap[pid] = true
	}
	var invalidPerms []string
	for _, pid := range permIDs {
		if !existMap[pid] {
			invalidPerms = append(invalidPerms, pid)
		}
	}

	return invalidPerms, len(invalidPerms) == 0
}

func (s *service) BindRolePerms(roleCode string, permIDs []string) error {
	// 1. 前置校验
	if roleCode == "" || len(permIDs) == 0 {
		return errors.New("the role code or permission ID list cannot be empty")
	}

	if err := s.db.Model(&model.PermissionRoleApi{}).Where("role_code = ?", roleCode).Delete().Error; err != nil {
		return errors.New("删除原有权限绑定失败：" + err.Error())
	}

	if err := s.db.Where("role_code = ?", roleCode).Delete(&model.PermissionRoleApi{}).Error; err != nil {
		s.l.Errorf("Failed to delete the original permission binding: %s", err.Error())
		return err
	}

	var perms = make([]model.PermissionRoleApi, 0)
	for _, d := range permIDs {
		perms = append(perms, model.PermissionRoleApi{
			RoleCode: roleCode,
			PermID:   d,
		})
	}

	if err := s.db.Model(&model.PermissionRoleApi{}).CreateInBatches(perms, len(perms)).Error; err != nil {
		s.l.Errorf("failed to batch bind, error: %s", err.Error)
		return err
	}

	return nil
}

func (s *service) CheckApiUnique(apiType, apiPath, apiMethod string) (bool, error) {
	if apiType == "" || apiPath == "" || apiMethod == "" {
		return false, errors.New("api type/path/method cannot be empty")
	}

	var count int64
	err := s.db.Model(&model.PermissionIotIdentityApi{}).
		Where("api_type = ? AND api_path = ? AND api_method = ?", apiType, apiPath, apiMethod).
		Count(&count).Error

	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *service) ListApiPerm(req *ApiPermListReq) (*ApiPermListResp, error) {
	var list []model.PermissionApi
	var total int64

	// 构建查询条件
	query := s.db.Model(&model.PermissionApi{})
	if req.ApiType != "" {
		query = query.Where("api_type = ?", req.ApiType)
	}
	if req.PermName != "" {
		query = query.Where("perm_name LIKE ?", "%"+req.PermName+"%")
	}

	// 统计总数
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	// 分页查询
	offset := (req.CurrentPage - 1) * req.PageSize
	if err := query.Offset(offset).Limit(req.PageSize).Find(&list).Error; err != nil {
		return nil, err
	}

	var resp = &ApiPermListResp{
		Detail: list,
		PageBaseResp: comm.PageBaseResp{
			Total: total,
		},
	}

	if int64(offset+req.PageSize) < total {
		resp.Next = true
	}

	return resp, nil
}

func (s *service) CheckPermIDExist(permID string) (bool, error) {
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

func (s *service) CheckApiUniqueExceptSelf(permID, apiType, apiPath, apiMethod string) (bool, error) {
	if permID == "" || apiType == "" || apiPath == "" || apiMethod == "" {
		s.l.Errorf("parma error, permID: %s, apiType: %s, apiPath: %s, apiMethod: %s", permID, apiType, apiPath, apiMethod)
		return false, errors.New("parma is invalid")
	}

	var count int64
	err := s.db.Model(&model.PermissionApi{}).
		Where("api_type = ? AND api_path = ? AND api_method = ? AND perm_id != ?", apiType, apiPath, apiMethod, permID).
		Count(&count).Error

	if err != nil {
		return false, err
	}
	return count > 0, nil
}
