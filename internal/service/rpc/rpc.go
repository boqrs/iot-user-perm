package rpc

import (
	"context"

	pb "github.com/boqrs/iot-user-perm/pkg/proto"
	logger "github.com/boqrs/zeus/log"
)

type GRPCServer struct {
	pb.UnimplementedIoTDevicePermissionServiceServer
	srv Service
	l   logger.Logger
}

func NewGRPCServer(permsrv Service, log logger.Logger) *GRPCServer {
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
