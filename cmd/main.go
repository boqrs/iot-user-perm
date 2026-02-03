package main

import (
	"fmt"
	"log"

	"github.com/boqrs/iot-user-perm/bootstrap"
	"github.com/boqrs/iot-user-perm/config"
	"github.com/boqrs/zeus"
	"github.com/boqrs/zeus/cmd"
	"github.com/boqrs/zeus/ginx"
)

func main() {
	cfg, err := config.GetConfig()
	if err != nil {
		log.Printf("failed to get config: %v\n", err)
		return
	}
	_ = cfg
	d := zeus.NewZeus()
	gcmd := cmd.NewGinCommand()
	// code must bigger than 100000
	if err := ginx.SetDefaultErrorCode(110000); err != nil {
		log.Fatalf("set default error code failed %v", err)
	}
	//add global gin middleware
	err = bootstrap.InitInfra(gcmd.ZeroGinRouter, cfg)
	if err != nil {
		log.Fatalf("init infra failed %v", err)
		return
	}

	if err := d.ZeusStart("test", gcmd); err != nil {
		fmt.Printf("zeus start error %v\n", err)
		return
	}
}
