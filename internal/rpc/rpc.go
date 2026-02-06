package rpc

import (
	"context"

	"github.com/boqrs/iot-user-perm/internal/service"
	pb "github.com/boqrs/iot-user-perm/pkg/proto"
	logger "github.com/boqrs/zeus/log"
)

type GRPCServer struct {
	pb.PermissionCenterServiceServer
	srv service.Service
	l   logger.Logger
}

func NewGRPCServer(permsrv service.Service, log logger.Logger) *GRPCServer {
	return &GRPCServer{
		srv: permsrv,
		l:   log.WithField("rpc", "grpc"),
	}
}

// ========== 1. 绑定设备 ==========
func (s *GRPCServer) BindDevice(ctx context.Context, req *pb.BindDeviceRequest) (*pb.BaseResponse, error) {
	return s.srv.BindDevice(ctx, req)
}

// ========== 2. 解绑设备 ==========
func (s *GRPCServer) UnbindDevice(ctx context.Context, req *pb.UnbindDeviceRequest) (*pb.BaseResponse, error) {
	return s.srv.UnbindDevice(ctx, req)
}

// ========== 3. 授权其他用户设备权限 ==========
func (s *GRPCServer) AuthorizeDevicePermission(ctx context.Context, req *pb.AuthorizeDevicePermissionRequest) (*pb.BaseResponse, error) {
	return s.srv.AuthorizeDevicePermission(ctx, req)
}

// ========== 4. 撤销其他用户设备权限 ==========
func (s *GRPCServer) RevokeDevicePermission(ctx context.Context, req *pb.RevokeDevicePermissionRequest) (*pb.BaseResponse, error) {
	return s.srv.RevokeDevicePermission(ctx, req)
}

// ========== 5. 查询用户设备权限 ==========
func (s *GRPCServer) GetDevicePermission(ctx context.Context, req *pb.GetDevicePermissionRequest) (*pb.GetDevicePermissionResponse, error) {
	return s.srv.GetDevicePermission(ctx, req)
}

// ========== 6. 批量删除设备所有权限 ==========
func (s *GRPCServer) BatchDeleteDevicePermission(ctx context.Context, req *pb.BatchDeleteDevicePermissionRequest) (*pb.BaseResponse, error) {
	return s.srv.BatchDeleteDevicePermission(ctx, req)
}

// ========== 7. 查询设备的所有权限用户列表 ==========
func (s *GRPCServer) GetDevicePermissionUsers(ctx context.Context, req *pb.GetDevicePermissionUsersRequest) (*pb.GetDevicePermissionUsersResponse, error) {
	return s.srv.GetDevicePermissionUsers(ctx, req)
}

// ========== 8. 批量查询用户的设备列表 ==========
func (s *GRPCServer) BatchGetUserDevices(ctx context.Context, req *pb.BatchGetUserDevicesRequest) (*pb.BatchGetUserDevicesResponse, error) {
	return s.srv.BatchGetUserDevices(ctx, req)
}

// ========== 8. 批量查询设备的权限 ==========
func (s *GRPCServer) BatchGetDevicePerms(ctx context.Context, req *pb.BatchGetDevicePermsRequest) (*pb.BatchGetDevicePermsResponse, error) {
	return s.srv.BatchGetDevicePerms(ctx, req)
}

// 【新增4个API权限管理接口】
func (s *GRPCServer) AddApiPerm(ctx context.Context, req *pb.AddApiPermRequest) (*pb.BaseResponse, error) {
	return s.AddApiPerm(ctx, req)
}
func (s *GRPCServer) UpdateApiPerm(ctx context.Context, req *pb.UpdateApiPermRequest) (*pb.BaseResponse, error) {
	return s.srv.UpdateApiPerm(ctx, req)
}
func (s *GRPCServer) DeleteApiPerm(ctx context.Context, req *pb.DeleteApiPermRequest) (*pb.BaseResponse, error) {
	return s.DeleteApiPerm(ctx, req)
}
func (s *GRPCServer) ListApiPerm(ctx context.Context, req *pb.ListApiPermRequest) (*pb.ListApiPermResponse, error) {
	return s.srv.ListApiPerm(ctx, req)
}

// 【新增7个角色管理接口】
func (s *GRPCServer) AddRole(ctx context.Context, req *pb.AddRoleRequest) (*pb.BaseResponse, error) {
	return s.srv.AddRole(ctx, req)
}
func (s *GRPCServer) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.BaseResponse, error) {
	return s.srv.UpdateRole(ctx, req)
}
func (s *GRPCServer) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*pb.BaseResponse, error) {
	return s.srv.DeleteRole(ctx, req)
}
func (s *GRPCServer) ListRole(ctx context.Context, req *pb.ListRoleRequest) (*pb.ListRoleResponse, error) {
	return s.srv.ListRole(ctx, req)
}
func (s *GRPCServer) BindRoleApi(ctx context.Context, req *pb.BindRoleApiRequest) (*pb.BaseResponse, error) {
	return s.srv.BindRoleApi(ctx, req)
}
func (s *GRPCServer) UnbindRoleApi(ctx context.Context, req *pb.UnbindRoleApiRequest) (*pb.BaseResponse, error) {
	return s.srv.UnbindRoleApi(ctx, req)
}
func (s *GRPCServer) ListRoleApi(ctx context.Context, req *pb.ListRoleApiRequest) (*pb.ListRoleApiResponse, error) {
	return s.srv.ListRoleApi(ctx, req)
}

// 【新增1个操作日志查询接口】
func (s *GRPCServer) ListOperLog(ctx context.Context, req *pb.ListOperLogRequest) (*pb.ListOperLogResponse, error) {
	return s.srv.ListOpLog(ctx, req)
}

// 【新增2个核心权限校验接口】
func (s *GRPCServer) CheckDevicePerm(ctx context.Context, req *pb.CheckDevicePermRequest) (*pb.CheckDevicePermResponse, error) {
	//TODO:
	return s.srv.CheckDevicePerm(ctx, req)
}
func (s *GRPCServer) CheckApiPerm(ctx context.Context, req *pb.CheckApiPermRequest) (*pb.CheckApiPermResponse, error) {
	//TODO:
	return s.srv
}
