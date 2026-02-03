package admin

import (
	"github.com/gin-gonic/gin"
)

type Service interface {
	AdminLogin(ctx *gin.Context, req *LoginReq) (*AdminLoginResp, error)
	AdminFirstPwd(ctx *gin.Context, req *FirstPwdReq) error
	AdminCreat(ctx *gin.Context, req *CreateAdminReq) (*CreateAdminResp, error)
	AdminDelete(ctx *gin.Context, userID string) error
	AdminPasswordUpdate(ctx *gin.Context, req *UpdatePwdReq) error
	AdminUserList(ctx *gin.Context, req *AdminListReq) (*AdminListResp, error)
	LogList(ctx *gin.Context, req *LogListReq) (*LogListResp, error)
	RolePerm(ctx *gin.Context, roleCode string) (*RolePermResp, error)
	BindRolePerm(ctx *gin.Context, req *BindRolePermReq) error
	AddApiPerm(ctx *gin.Context, req *AddApiPermReq) (*AddApiPermResp, error)
	UpdateApiPerm(ctx *gin.Context, req *UpdateApiPermReq) error
	DelApiPerm(ctx *gin.Context, permId string) error
	PermList(ctx *gin.Context, req *ApiPermListReq) (*ApiPermListResp, error)
	IOTRolePerm(ctx *gin.Context, roleCode string) (*RolePermResp, error)
	IotApiPermBind(ctx *gin.Context, req *BindIotIdentityPermReq) error
	DelIotApiPerm(ctx *gin.Context, permId int64) error
}
