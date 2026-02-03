package admin

import (
	"net/http"
	"strconv"
	"time"

	amSrv "github.com/boqrs/iot-user-perm/internal/service/admin"
	"github.com/boqrs/iot-user-perm/pkg/errs"
	"github.com/boqrs/iot-user-perm/pkg/middleware"
	"github.com/boqrs/zeus"
	ginx2 "github.com/boqrs/zeus/ginx"
	logger "github.com/boqrs/zeus/log"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	router ginx2.ZeroGinRouter
	amSrv  amSrv.Service
	log    logger.Logger
}

func InitHandler(r ginx2.ZeroGinRouter, amSrv amSrv.Service, l logger.Logger) zeus.Service {
	return &Handler{
		router: r,
		amSrv:  amSrv,
		log:    l.WithField("handler", "admin")}
}

func (h *Handler) RouterRegister() {
	group := h.router.Group("/api/v1/external")
	group.Handle(http.MethodPost, "/xiling/permission/admin_user/login", h.login)
	group.Handle(http.MethodPut, "/xiling/permission/admin_user/first-pwd", h.firstPwd)

	//TODO: 配置管理账号，操作日志，用户数据 只有超级用户有权限
	groupSuper := h.router.Group("/api/v1/external")
	groupSuper.Use(middleware.JWTAuth(h.log)).Use(middleware.SuperAdminAuth(h.log))
	groupSuper.Handle(http.MethodPost, "/xiling/permission/admin_user/create", h.adminCreat)
	groupSuper.Handle(http.MethodDelete, "/xiling/permission/admin_user/delete/:userId", h.adminDelete)
	groupSuper.Handle(http.MethodGet, "/xiling/permission/admin_user/list", h.adminList)
	groupSuper.Handle(http.MethodGet, "/xiling/permission/admin_user/log_list", h.logList)

	//TODO：配置 perm api， 以及iot perm api 管理员都有权限
	groupManage := h.router.Group("/api/v1/external")
	groupManage.Use(middleware.JWTAuth(h.log), middleware.AdminAuth(h.log))
	groupManage.Handle(http.MethodPost, "/xiling/permission/admin_user/password/update", h.passwordUpdate)
	groupManage.Handle(http.MethodGet, "/xiling/permission/role_perm/:roleCode", h.GetRolePerm)
	groupManage.Handle(http.MethodPost, "/xiling/permission/role_perm/bind", h.addRolePerm)
	groupManage.Handle(http.MethodPost, "/xiling/permission/api_perm/add", h.addApiPerm)
	groupManage.Handle(http.MethodPost, "/xiling/permission/api_perm/update/{permId}", h.updateApiPerm)
	groupManage.Handle(http.MethodDelete, "/xiling/permission/api_perm/delete/{permId}", h.delApiPerm)
	groupManage.Handle(http.MethodGet, "/xiling/permission/api_perm/list", h.permList)
	groupManage.Handle(http.MethodGet, "/xiling/permission/iot/identity/api_perm/{identityCode}", h.GetIotRolePerm)
	groupManage.Handle(http.MethodPost, "/xiling/permission/iot/api_perm/bind", h.iotApiPermBind)
	groupManage.Handle(http.MethodPost, "/xiling/permission/iot/api_perm/delete/{iotPermID}", h.delIotApiPerm)

}

func (h *Handler) login(ctx *gin.Context) ginx2.Render {
	var req amSrv.FirstPwdReq
	var err error

	if err = ctx.ShouldBind(&req); err != nil {
		h.log.Errorf("failed to bind: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	err = h.amSrv.AdminFirstPwd(ctx, &req)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}
	return ginx2.Success(nil)
}

func (h *Handler) firstPwd(ctx *gin.Context) ginx2.Render {
	var req amSrv.LoginReq
	var err error

	if err = ctx.ShouldBind(&req); err != nil {
		h.log.Errorf("failed to bind: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	resp, err := h.amSrv.AdminLogin(ctx, &req)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}
	return ginx2.Success(resp)
}

func (h *Handler) adminCreat(ctx *gin.Context) ginx2.Render {
	var req amSrv.CreateAdminReq
	var err error

	if err = ctx.ShouldBind(&req); err != nil {
		h.log.Errorf("failed to bind: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	resp, err := h.amSrv.AdminCreat(ctx, &req)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}
	return ginx2.Success(resp)
}

func (h *Handler) adminDelete(ctx *gin.Context) ginx2.Render {

	userID := ctx.Param("userId")
	if userID == "" {
		h.log.Errorf("failed find param")
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	if err := h.amSrv.AdminDelete(ctx, userID); err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(nil)
}

func (h *Handler) passwordUpdate(ctx *gin.Context) ginx2.Render {

	var req amSrv.UpdatePwdReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		h.log.Errorf("failed to bind: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	if err := h.amSrv.AdminPasswordUpdate(ctx, &req); err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(nil)
}

func (h *Handler) adminList(ctx *gin.Context) ginx2.Render {

	var req amSrv.AdminListReq
	if err := ctx.ShouldBindQuery(&req); err != nil {
		h.log.Errorf("param error: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	resp, err := h.amSrv.AdminUserList(ctx, &req)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(resp)
}

func (h *Handler) logList(ctx *gin.Context) ginx2.Render {

	var req amSrv.LogListReq
	if err := ctx.ShouldBindQuery(&req); err != nil {
		h.log.Errorf("param error: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	if req.StartTime != "" && req.EndTime != "" {
		start, _ := time.Parse("2006-01-02 15:04:05", req.StartTime)
		end, _ := time.Parse("2006-01-02 15:04:05", req.EndTime)
		if start.After(end) {
			h.log.Errorf("Reset administrator password")
			return ginx2.Error(errs.NewError(errs.InvalidRequest))
		}
	}

	resp, err := h.amSrv.LogList(ctx, &req)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(resp)
}

func (h *Handler) GetRolePerm(ctx *gin.Context) ginx2.Render {

	roleCode := ctx.Param("roleCode")
	if roleCode == "" {
		h.log.Errorf("Role code is required.")
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	currentRole := ctx.MustGet("roleCode").(string)
	if currentRole == "ADMIN" && roleCode != "ADMIN" {
		h.log.Errorf("Can only view own role permissions.")
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	resp, err := h.amSrv.RolePerm(ctx, roleCode)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(resp)
}

func (h *Handler) addRolePerm(ctx *gin.Context) ginx2.Render {

	var req amSrv.BindRolePermReq
	if err := ctx.ShouldBind(&req); err != nil {
		h.log.Errorf("failed to bind: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	if err := h.amSrv.BindRolePerm(ctx, &req); err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(nil)
}

func (h *Handler) addApiPerm(ctx *gin.Context) ginx2.Render {

	var req amSrv.AddApiPermReq
	if err := ctx.ShouldBind(&req); err != nil {
		h.log.Errorf("failed to bind: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	resp, err := h.amSrv.AddApiPerm(ctx, &req)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(resp)
}

func (h *Handler) permList(ctx *gin.Context) ginx2.Render {
	var req amSrv.ApiPermListReq
	if err := ctx.ShouldBindQuery(&req); err != nil {
		h.log.Errorf("request param error: %#v", req)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	resp, err := h.amSrv.PermList(ctx, &req)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(resp)
}

func (h *Handler) updateApiPerm(ctx *gin.Context) ginx2.Render {

	permID := ctx.Param("permId")
	if permID == "" {
		h.log.Errorf("perm id is empty")
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	var req amSrv.UpdateApiPermReq
	req.PermId = permID
	if err := ctx.ShouldBind(&req); err != nil {
		h.log.Errorf("failed to bind: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	if err := h.amSrv.UpdateApiPerm(ctx, &req); err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(nil)
}

func (h *Handler) delApiPerm(ctx *gin.Context) ginx2.Render {

	permID := ctx.Param("permId")
	if permID == "" {
		h.log.Errorf("perm id is empty")
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	if err := h.amSrv.DelApiPerm(ctx, permID); err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(nil)
}

func (h *Handler) GetIotRolePerm(ctx *gin.Context) ginx2.Render {
	roleCode := ctx.Param("identityCode")
	if roleCode == "" {
		h.log.Errorf("identityCode is required.")
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	resp, err := h.amSrv.IOTRolePerm(ctx, roleCode)
	if err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(resp)
}

func (h *Handler) iotApiPermBind(ctx *gin.Context) ginx2.Render {

	var req amSrv.BindIotIdentityPermReq
	if err := ctx.ShouldBind(&req); err != nil {
		h.log.Errorf("failed to bind: %s", err.Error)
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	if err := h.amSrv.IotApiPermBind(ctx, &req); err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(nil)
}

func (h *Handler) delIotApiPerm(ctx *gin.Context) ginx2.Render {
	permID := ctx.Param("iotPermID")
	if permID == "" {
		h.log.Errorf("perm id is empty")
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	value, err := strconv.ParseInt(permID, 10, 64)
	if err != nil {
		h.log.Errorf("perm is not int")
		return ginx2.Error(errs.NewError(errs.InvalidRequest))
	}

	if err := h.amSrv.DelIotApiPerm(ctx, value); err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(nil)
}
