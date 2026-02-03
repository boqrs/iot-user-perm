package admin

import (
	"errors"
	"fmt"
	"strings"

	"github.com/boqrs/comm/database/cache"
	"github.com/boqrs/iot-user-perm/config"
	"github.com/boqrs/iot-user-perm/pkg/comm"
	"github.com/boqrs/iot-user-perm/pkg/model"
	"github.com/boqrs/iot-user-perm/pkg/utils"
	logger "github.com/boqrs/zeus/log"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type service struct {
	db    *gorm.DB
	cache cache.Cache
	cfg   *config.Config
	l     logger.Logger
}

func InitRegisterService(sql *gorm.DB, cfg *config.Config, ch cache.Cache, l logger.Logger) Service {
	s := &service{
		db:    sql,
		cfg:   cfg,
		cache: ch,
		l:     l.WithField("services", "admin")}

	return s
}

func (s *service) AdminLogin(ctx *gin.Context, req *LoginReq) (*AdminLoginResp, error) {
	resp, err := s.GetByUsername(req.Username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			s.l.Errorf("user: %s not found", req.Username)
		}
		return nil, err
	}

	if !utils.BcryptVerify(req.Password, resp.Password) {
		s.l.Printf("user: %s, password is error", req.Username)
		return nil, errors.New("password error")
	}

	if resp.Status != "ENABLED" {
		s.l.Errorf("account: %s is not enable", req.Username)
		return nil, errors.New("account is not enable")
	}

	token, err := utils.GenerateToken(resp.UserID, resp.Username, resp.RoleCode)
	if err != nil {
		s.l.Errorf("failed to generate token, error: %s", err.Error())
		return nil, err
	}

	if err = s.RecordLoginLog(resp.UserID, resp.Username, req.IP, "adin_login", "success", ""); err != nil {
		s.l.Errorf("failed to record login")
	}

	return &AdminLoginResp{
		Token:        token,
		Username:     resp.Username,
		UserId:       resp.UserID,
		RoleCode:     resp.RoleCode,
		IsFirstLogin: resp.IsFirstLogin == 1,
	}, nil
}

func (s *service) AdminFirstPwd(ctx *gin.Context, req *FirstPwdReq) error {
	if !utils.CheckPasswordComplexity(req.NewPassword) {
		s.l.Errorf("The new password must contain uppercase and lowercase letters, digits, and special characters, with a length of at least 8 characters.")
		return errors.New("the new password must contain uppercase and lowercase letters, digits, and special characters, with a length of at least 8 characters")
	}

	userID := ctx.MustGet("userID").(string)
	admin, err := s.GetByUserID(userID)
	if err != nil {
		s.l.Errorf("failed to find user, error: %s", err.Error())
		return errors.New("user not existed")
	}

	if admin.IsFirstLogin != 1 {
		s.l.Info("If this is not your first login, there is no need to change your initial password.")
		return nil
	}

	if !utils.BcryptVerify(req.OldPassword, admin.Password) {
		s.l.Errorf("old password is error")
		return errors.New("old password is error")
	}

	newPwd, err := utils.BcryptEncrypt(req.NewPassword)
	if err != nil {
		s.l.Errorf("password encryption failed, error: %s", err.Error())
		return errors.New("password encryption failed")
	}

	if err = s.UpdatePassword(userID, newPwd); err != nil {
		s.l.Errorf("failed to update password, error: %s", err.Error())
		return errors.New("failed to update password")
	}

	if err = s.UpdateFirstLogin(userID); err != nil {
		s.l.Errorf("failed to update first login, error: %s", err.Error())
		return errors.New("failed to update first login")
	}

	if err = s.RecordLoginLog(userID, admin.Username, req.IP, "first_password", "success", ""); err != nil {
		s.l.Errorf("failed to record login")
	}

	return nil
}

func (s *service) AdminCreat(ctx *gin.Context, req *CreateAdminReq) (*CreateAdminResp, error) {
	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)
	operIP := ctx.ClientIP()

	resp, err := s.CreateAdmin(req, operatorID, operatorName, operIP)
	if err != nil {
		s.l.Errorf("failed to create admin, error: %s", err.Error())
		return nil, err
	}

	return &CreateAdminResp{
		UserID:   resp.UserID,
		Username: resp.Username,
		Status:   resp.Status,
	}, nil
}

func (s *service) AdminDelete(ctx *gin.Context, userID string) error {
	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)
	operIP := ctx.ClientIP()

	admin, err := s.GetByUserID(userID)
	if err != nil {
		s.l.Errorf("failed to find user: %s, error: %s", userID, err.Error())
		return err
	}

	if admin.RoleCode == "SUPER_ADMIN" {
		s.l.Errorf("supper manager can not be deleted")
		return errors.New("supper manager can not be deleted")
	}

	if err = s.Delete(userID); err != nil {
		s.l.Errorf("failed to delete user: %s, error: %s", userID, err.Error())
		return err
	}

	opLog := &model.PermissionOperationLog{
		LogID:        uuid.NewString(),
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "delete_admin",
		OperContent:  fmt.Sprintf("create admin %s", admin.Username),
		OperIP:       operIP,
		OperResult:   "success",
		ErrorMsg:     "",
	}

	if err := s.CreateLog(opLog); err != nil {
		s.l.Errorf("failed to create log: %#v, error: %s", opLog, err.Error())
	}

	return nil
}

func (s *service) AdminPasswordUpdate(ctx *gin.Context, req *UpdatePwdReq) error {
	if !utils.CheckPasswordComplexity(req.NewPassword) {
		s.l.Errorf("The new password must contain uppercase and lowercase letters, digits, and special characters, with a length of at least 8 characters.")
		return errors.New("the new password must contain uppercase and lowercase letters, digits, and special characters, with a length of at least 8 characters")
	}

	operatorID := ctx.MustGet("userID").(string)
	operatorRole := ctx.MustGet("roleCode").(string)
	operatorName := ctx.MustGet("username").(string)
	operIP := ctx.ClientIP()

	var targetUserID string
	if req.TargetUserID != "" {
		if operatorRole != "SUPER_ADMIN" {
			s.l.Errorf("Only super administrators can reset other users' passwords.")
			return errors.New("not support")
		}
		targetUserID = req.TargetUserID
		admin, err := s.GetByUserID(targetUserID)
		if err != nil || admin.RoleCode == "SUPER_ADMIN" {
			s.l.Errorf("The target user either does not exist or is a super administrator.\n\n")
			return errors.New("not manager")
		}
	} else {
		targetUserID = operatorID
		admin, err := s.GetByUserID(targetUserID)
		if err != nil {
			s.l.Errorf("failed to find target user, error: %s", err)
			return err
		}

		if !utils.BcryptVerify(req.OldPassword, admin.Password) {
			s.l.Errorf("password error")
			return errors.New("password error")
		}
	}

	// 步骤5：加密新密码并更新
	newPwd, err := utils.BcryptEncrypt(req.NewPassword)
	if err != nil {
		s.l.Errorf("password encryption failed, error: %s", err.Error())
		return errors.New("password encryption failed")
	}

	if err = s.UpdatePassword(targetUserID, newPwd); err != nil {
		s.l.Errorf("failed to change password, error: %s", err.Error())
		return err
	}

	// 步骤6：记录日志
	operType := "Self-Service Password Change/Reset"
	if req.TargetUserID != "" {
		operType = "Reset administrator password"
	}

	opLog := &model.PermissionOperationLog{
		LogID:        uuid.NewString(),
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     operType,
		OperContent:  fmt.Sprintf("change user:%s password", targetUserID),
		OperIP:       operIP,
		OperResult:   "success",
	}

	if err = s.CreateLog(opLog); err != nil {
		s.l.Errorf("failed to create log, error: %s", err.Error())
	}

	return nil
}

func (s *service) AdminUserList(ctx *gin.Context, req *AdminListReq) (*AdminListResp, error) {
	total, resp, err := s.List(req)
	if err != nil {
		s.l.Errorf("failed to list admin user, error: %s", err.Error())
		return nil, err
	}

	rp := &AdminListResp{
		Detail: resp,
		PageBaseResp: comm.PageBaseResp{
			Total: total,
		},
	}
	offset := (req.CurrentPage - 1) * req.PageSize

	if int64(offset+req.PageSize) < total {
		rp.Next = true
	}

	return rp, nil
}

func (s *service) LogList(ctx *gin.Context, req *LogListReq) (*LogListResp, error) {
	//只有super manage才有权限看数据，权限的校验在外层解决
	return s.logList(req)
}

func (s *service) RolePerm(ctx *gin.Context, roleCode string) (*RolePermResp, error) {

	var role model.PermissionRole
	if err := s.db.Model(&model.PermissionRole{}).Where("role_code = ?", roleCode).First(&role).Error; err != nil {
		s.l.Errorf("failed to find role, error: %s", err.Error())
		return nil, err
	}

	var pmers []model.PermissionRoleApi
	if err := s.db.Model(&model.PermissionRoleApi{}).Where("role_code = ?", role).Find(&pmers).Error; err != nil {
		s.l.Errorf("failed to find perms, error: %s", err.Error())
		return nil, err
	}

	resp := &RolePermResp{
		RoleCode: roleCode,
		RoleName: role.RoleName,
		PermList: pmers,
	}
	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)
	opLog := &model.PermissionOperationLog{
		LogID:        uuid.NewString(),
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "role_perm query",
		OperContent:  fmt.Sprintf("query %s perm", roleCode),
		OperIP:       ctx.ClientIP(),
		OperResult:   "success",
	}

	if err := s.CreateLog(opLog); err != nil {
		s.l.Errorf("failed to create log, error: %s", err.Error())
	}

	return resp, nil
}

func (s *service) BindRolePerm(ctx *gin.Context, req *BindRolePermReq) error {
	invalidIds, has := s.CheckPermIDsExist(req.PermissionIds)
	if !has {
		s.l.Errorf("request: %#v, the permission ID is invalid: %#v", req, invalidIds)
		return errors.New("failed to check perms")
	}

	if err := s.BindRolePerms(req.RoleCode, req.PermissionIds); err != nil {
		s.l.Errorf("failed to bind role perm, error: %s", err.Error())
		return err
	}

	return nil
}

func (s *service) AddApiPerm(ctx *gin.Context, req *AddApiPermReq) (*AddApiPermResp, error) {
	exist, err := s.CheckApiUnique(req.ApiType, req.ApiPath, req.ApiMethod)
	if err != nil {
		s.l.Errorf("failed to check unique, error: %s", err.Error())
		return nil, err
	}

	if exist {
		s.l.Errorf("The API permission already exists.")
		return nil, errors.New("the API permission already exists")
	}

	permID := "perm" + uuid.NewString()
	pp := &model.PermissionApi{
		PermID:    permID,
		PermName:  req.PermName,
		ApiType:   req.ApiType,
		ApiPath:   req.ApiPath,
		ApiMethod: req.ApiMethod,
		Remark:    req.Remark,
	}
	if err = s.db.Model(&model.PermissionApi{}).Create(pp).Error; err != nil {
		s.l.Errorf("failed to create PermissionApi, error: %s", err.Error())
		return nil, err
	}

	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)
	if err := s.CreateLog(&model.PermissionOperationLog{
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "add perm api",
		OperContent:  fmt.Sprintf("permID：%s，name：%s，api：%s %s", permID, req.PermName, req.ApiMethod, req.ApiPath),
		OperIP:       ctx.ClientIP(),
		OperResult:   "success",
	}); err != nil {
		s.l.Errorf("failed to save oplog, error: %s", err.Error())
	}

	return &AddApiPermResp{
		PermID:   permID,
		PermName: req.PermName,
	}, nil
}

func (s *service) PermList(ctx *gin.Context, req *ApiPermListReq) (*ApiPermListResp, error) {
	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)

	if err := s.CreateLog(&model.PermissionOperationLog{
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "query api permission list",
		OperContent:  fmt.Sprintf("page：%d/%d，type：%s，name：%s", req.CurrentPage, req.PageSize, req.ApiType, req.PermName),
		OperIP:       ctx.ClientIP(),
		OperResult:   "success",
	}); err != nil {
		s.l.Errorf("failed to save oplog, error: %s", err.Error())
	}

	return s.ListApiPerm(req)
}

func (s *service) UpdateApiPerm(ctx *gin.Context, req *UpdateApiPermReq) error {
	exist, err := s.CheckPermIDExist(req.PermId)
	if err != nil {
		s.l.Errorf("Failed to verify permission ID: %s", err.Error())
		return err
	}
	if !exist {
		s.l.Errorf("The permission ID is invalid: %s", err.Error())
		return nil
	}

	exist, err = s.CheckApiUniqueExceptSelf(req.PermId, req.ApiType, req.ApiPath, req.ApiMethod)
	if err != nil {
		s.l.Errorf("Failed to verify API uniqueness:: %s", err.Error())
		return err
	}

	if exist {
		s.l.Errorf("API permission already exists.")
		return errors.New("api permission already exists")
	}

	var ups = make(map[interface{}]interface{}, 0)
	if req.ApiPath != "" {
		ups["api_path"] = req.ApiPath
	}
	if req.ApiType != "" {
		ups["api_type"] = req.ApiType
	}
	if req.PermName != "" {
		ups["perm_name"] = req.PermName
	}
	if req.ApiMethod != "" {
		ups["api_method"] = req.ApiMethod
	}
	if req.Remark != "" {
		ups["remark"] = req.Remark
	}

	if err = s.db.Model(&model.PermissionApi{}).Where("perm_id = ?", req.PermId).Updates(ups).Error; err != nil {
		s.l.Errorf("failed to update api: %#v, error: %s", req, err.Error())
		return err
	}

	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)
	if err := s.CreateLog(&model.PermissionOperationLog{
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "update api perm",
		OperContent:  fmt.Sprintf("api：%s，type：%s，name：%s", req.ApiPath, req.ApiType, req.PermName),
		OperIP:       ctx.ClientIP(),
		OperResult:   "success",
	}); err != nil {
		s.l.Errorf("failed to save oplog, error: %s", err.Error())
	}

	return nil
}

func (s *service) DelApiPerm(ctx *gin.Context, permId string) error {
	exist, err := s.CheckPermIDExist(permId)
	if err != nil {
		s.l.Errorf("Failed to verify permission ID: %s", err.Error())
		return err
	}
	if !exist {
		s.l.Errorf("The permission ID is invalid: %s", err.Error())
		return nil
	}

	//TODO: 这里可能需要清理一些数据
	if err = s.db.Model(&model.PermissionApi{}).Where("perm_id = ?", permId).Delete(&model.PermissionApi{}).Error; err != nil {
		s.l.Errorf("failed to delete api, error: %s", err.Error())
		return err
	}

	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)
	if err := s.CreateLog(&model.PermissionOperationLog{
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "delete api perm",
		OperContent:  fmt.Sprintf("api：%s", permId),
		OperIP:       ctx.ClientIP(),
		OperResult:   "success",
	}); err != nil {
		s.l.Errorf("failed to save oplog, error: %s", err.Error())
	}

	return nil
}

func (s *service) IOTRolePerm(ctx *gin.Context, identityCode string) (*IotRolePermResp, error) {
	exist, err := s.CheckIdentityExist(identityCode)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, errors.New("identity not existed")
	}

	perms, err := s.GetIdentityPerms(identityCode)
	if err != nil {
		return nil, err
	}

	return &IotRolePermResp{
		IdentityCode: identityCode,
		IdentityName: s.GetIdentityName(identityCode),
		PermList:     perms,
	}, nil

}

func (s *service) IotApiPermBind(ctx *gin.Context, req *BindIotIdentityPermReq) error {
	exist, err := s.CheckIdentityExist(req.IdentityCode)
	if err != nil {
		return err
	}
	if !exist {
		return errors.New("identity not existed")
	}

	exist, invalidPerms, nonIotPerms := s.CheckIotPermIDsExist(req.PermissionIds)
	if !exist {
		s.l.Errorf("perm id not existed: " + strings.Join(invalidPerms, ","))
		return errors.New("perm id not existed")
	}
	if len(nonIotPerms) > 0 {
		s.l.Errorf("perm type is not iot: " + strings.Join(nonIotPerms, ","))
		return errors.New("perm type error")
	}

	iotapis := make([]model.PermissionIotIdentityApi, 0)
	for _, perm := range invalidPerms {
		iotapis = append(iotapis, model.PermissionIotIdentityApi{
			IdentityCode: req.IdentityCode,
			PermID:       perm,
		})
	}

	if err = s.db.Model(&model.PermissionIotIdentity{}).CreateInBatches(iotapis, len(iotapis)).Error; err != nil {
		s.l.Errorf("failed to batch create iot apis, error: %s", err.Error())
		return err
	}

	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)
	if err := s.CreateLog(&model.PermissionOperationLog{
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "add iot api perm",
		OperContent:  fmt.Sprintf("apis：%s", invalidPerms),
		OperIP:       ctx.ClientIP(),
		OperResult:   "success",
	}); err != nil {
		s.l.Errorf("failed to save oplog, error: %s", err.Error())
	}

	return nil
}

func (s *service) DelIotApiPerm(ctx *gin.Context, permId int64) error {
	if permId == 0 {
		return errors.New("permID should not be zero")
	}

	if err := s.db.Model(&model.PermissionIotIdentityApi{}).Where("id  = ?", permId).
		Delete(&model.PermissionIotIdentityApi{}).Error; err != nil {
		s.l.Errorf("failed to delete iot api perm: %d, error: %s", permId, err.Error())
	}

	operatorID := ctx.MustGet("userID").(string)
	operatorName := ctx.MustGet("username").(string)
	if err := s.CreateLog(&model.PermissionOperationLog{
		OperatorID:   operatorID,
		OperatorName: operatorName,
		OperType:     "delete iot api perm",
		OperContent:  fmt.Sprintf("api：%s", permId),
		OperIP:       ctx.ClientIP(),
		OperResult:   "success",
	}); err != nil {
		s.l.Errorf("failed to save oplog, error: %s", err.Error())
	}

	return nil
}
