package bootstrap

import (
	"context"
	"fmt"
	"net"

	"github.com/boqrs/comm/database/sql"
	"github.com/boqrs/comm/log"
	"github.com/boqrs/comm/redis"
	"github.com/boqrs/iot-user-perm/config"
	"github.com/boqrs/iot-user-perm/internal/handler/admin"
	adsrv "github.com/boqrs/iot-user-perm/internal/service/admin"
	"github.com/boqrs/iot-user-perm/pkg/comm"
	"github.com/boqrs/zeus/ginx"
)

func InitInfra(engine ginx.ZeroGinRouter, cfg *config.Config) error {
	l, err := log.InitLogger(cfg.Log)
	if err != nil {
		return err
	}

	var cli redis.RedisClient
	if cfg.Global.Env != comm.EnvPro && cfg.Global.Env != comm.EnvTest {
		cli, err = redis.NewRedisClient(cfg.Redis)
	} else {
		cli, err = redis.NewRedisClusterClient(cfg.Redis)
	}

	if err != nil {
		l.WithField("pkg", "bootstrap").Errorf("failed to create redis client: %v", err)
		return err
	}

	gr, err := sql.NewGorm(&cfg.Sql, &cfg.Con, l)
	if err != nil {
		l.WithField("pkg", "bootstrap").Errorf("failed to create pg client: %v", err)
		return err
	}

	adminSrv := adsrv.InitRegisterService(gr, cfg, cli, l)
	admin.InitHandler(engine, adminSrv, l).RouterRegister()

	//TODO: 异步启动一个grpc server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	grpcServer := server.NewGRPCServer(cfg, l) // 你的gRPC服务初始化函数
	grpcListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Grpc.Host, cfg.Grpc.Port))
	if err != nil {
		l.Error("failed to create grpc server", "error", err)
		return err
	}

	return nil
}
