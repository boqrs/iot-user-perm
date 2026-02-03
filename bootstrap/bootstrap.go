package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/boqrs/comm/database/sql"
	"github.com/boqrs/comm/email"
	"github.com/boqrs/comm/log"
	"github.com/boqrs/comm/redis"
	"github.com/boqrs/iot-user-perm/config"
	"github.com/boqrs/iot-user-perm/pkg/comm"
	"github.com/boqrs/zeus/ginx"
	"google.golang.org/grpc"
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

	if err = util.InitGeoIP("./config/GeoLite2-Country.mmdb"); err != nil {
		panic(errors.New("failed to init geoip"))
	}

	eSrv := email.InitEmailService(cfg.Email.Server, cfg.Email.UserName, cfg.Email.Password)
	regSrv := regSrv.InitRegisterService(gr, cfg, cli, eSrv, l)
	authSrv := authSrv.InitRegisterService(gr, cfg, cli, l)

	reg.InitHandler(engine, regSrv, l).RouterRegister()
	auth.InitHandler(engine, authSrv, l).RouterRegister()

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(unaryLogInterceptor), // 一元拦截器（处理单个请求）
	)
	rpc2.RegisterAuthServiceServer(grpcServer, &rpc.RpcService{})
	return nil
}

func unaryLogInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,

) (interface{}, error) {
	// 记录请求开始时间
	startTime := time.Now()
	// 执行实际的接口处理
	resp, err := handler(ctx, req)
	// 记录日志（接口名、耗时、错误）
	fmt.Printf(
		"gRPC请求 | 接口：%s | 耗时：%v | 错误：%v",
		info.FullMethod,
		time.Since(startTime),
		err,
	)
	return resp, err
}
