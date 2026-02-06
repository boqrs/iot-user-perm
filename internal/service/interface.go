package service

import (
	"context"

	pb "github.com/boqrs/iot-user-perm/pkg/proto"
)

type Service interface {
	BindDevice(ctx context.Context, req *pb.BindDeviceRequest) (*pb.BaseResponse, error)
	UnbindDevice(ctx context.Context, req *pb.UnbindDeviceRequest) (*pb.BaseResponse, error)
	AuthorizeDevicePermission(ctx context.Context, req *pb.AuthorizeDevicePermissionRequest) (*pb.BaseResponse, error)
	RevokeDevicePermission(ctx context.Context, req *pb.RevokeDevicePermissionRequest) (*pb.BaseResponse, error)
	GetDevicePermission(ctx context.Context, req *pb.GetDevicePermissionRequest) (*pb.GetDevicePermissionResponse, error)
	GetDevicePermissionUsers(ctx context.Context, req *pb.GetDevicePermissionUsersRequest) (*pb.GetDevicePermissionUsersResponse, error)
	BatchDeleteDevicePermission(ctx context.Context, req *pb.BatchDeleteDevicePermissionRequest) (*pb.BaseResponse, error)
	BatchGetDevicePerms(ctx context.Context, req *pb.BatchGetDevicePermsRequest) (*pb.BatchGetDevicePermsResponse, error)
	BatchGetUserDevices(ctx context.Context, req *pb.BatchGetUserDevicesRequest) (*pb.BatchGetUserDevicesResponse, error)
	//新增加
	AddApiPerm(ctx context.Context, req *pb.AddApiPermRequest) (*pb.BaseResponse, error)
	AddRole(ctx context.Context, req *pb.AddRoleRequest) (*pb.BaseResponse, error)
	BindRoleApi(ctx context.Context, req *pb.BindRoleApiRequest) (*pb.BaseResponse, error)
	UpdateApiPerm(ctx context.Context, req *pb.UpdateApiPermRequest) (*pb.BaseResponse, error)
	DeleteApiPerm(ctx context.Context, req *pb.DeleteApiPermRequest) (*pb.BaseResponse, error)
	ListApiPerm(ctx context.Context, req *pb.ListApiPermRequest) (*pb.ListApiPermResponse, error)
	UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.BaseResponse, error)
	DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*pb.BaseResponse, error)
	ListRole(ctx context.Context, req *pb.ListRoleRequest) (*pb.ListRoleResponse, error)
	UnbindRoleApi(ctx context.Context, req *pb.UnbindRoleApiRequest) (*pb.BaseResponse, error)
	ListRoleApi(ctx context.Context, req *pb.ListRoleApiRequest) (*pb.ListRoleApiResponse, error)
	ListOpLog(ctx context.Context, req *pb.ListOperLogRequest) (*pb.ListOperLogResponse, error)
	CheckDevicePerm(ctx context.Context, req *pb.CheckDevicePermRequest) (*pb.CheckDevicePermResponse, error)
}
