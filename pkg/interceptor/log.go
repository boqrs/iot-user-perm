package interceptor

import (
	"context"
	"time"

	logger "github.com/boqrs/zeus/log"
	"google.golang.org/grpc"
)

func LoggingInterceptor(log logger.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		start := time.Now()
		log.Infof("gRPC request start, method: %s", info.FullMethod)
		defer func() {
			duration := time.Since(start)

			if err == nil {
				log.Infof("gRPC request finish, method: %s, duration: %v", info.FullMethod, duration)
			} else {
				log.Errorf("gRPC request finish, method: %s, duration: %v, error: %s", info.FullMethod, duration, err.Error())
			}
		}()
		return handler(ctx, req)
	}
}
