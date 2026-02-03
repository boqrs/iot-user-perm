package admin

import (
	"net/http"
	"time"

	amSrv "github.com/boqrs/iot-user-perm/internal/service/admin"
	"github.com/boqrs/iot-user-perm/pkg/errs"
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
	group.Handle(http.MethodPost, "/xiling/admin/user/login", h.login)
	group.Handle(http.MethodPut, "/xiling/admin/user/first-pwd", h.firstPwd)

	group.Handle(http.MethodPost, "/xiling/admin/user/create", h.adminCreat)
	group.Handle(http.MethodDelete, "/xiling/admin/user/delete/:userId", h.adminDelete)
	group.Handle(http.MethodPost, "/xiling/admin/user/password/update", h.passwordUpdate)
	group.Handle(http.MethodGet, "/xiling/admin/user/list", h.adminList)
	group.Handle(http.MethodGet, "/xiling/admin/user/log_list", h.logList)

	group.Handle(http.MethodGet, "/xiling/admin/user/role_perm/:roleCode", h.GetRolePerm)
	group.Handle(http.MethodPost, "/xiling/admin/user/role_perm/bind", h.addRolePerm)
	group.Handle(http.MethodPost, "/xiling/admin/user/api_perm/add", h.addApiPerm)
	group.Handle(http.MethodPost, "/xiling/admin/user/api_perm/update/{permId}", h.updateApiPerm)
	group.Handle(http.MethodDelete, "/xiling/admin/user/api_perm/delete/{permId}", h.delApiPerm)

	group.Handle(http.MethodGet, "/xiling/admin/user/api_perm/list", h.permList)
	group.Handle(http.MethodPost, "/xiling/admin/user/perm/identityCode", h.active)
	group.Handle(http.MethodPost, "/xiling/admin/user/iot_perm/bind", h.active)

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

	if err := h.amSrv.AddApiPerm(ctx, &req); err != nil {
		return ginx2.Error(errs.NewError(errs.Internal))
	}

	return ginx2.Success(nil)
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
