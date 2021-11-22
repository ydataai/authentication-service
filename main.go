package main

import (
	"fmt"
	"os"

	"github.com/ydataai/go-core/pkg/common/config"
	"github.com/ydataai/go-core/pkg/common/logging"
)

func main() {
	loggerConfiguration := logging.LoggerConfiguration{}

	if err := config.InitConfigurationVariables([]config.ConfigurationVariables{
		&loggerConfiguration,
	}); err != nil {
		fmt.Println(fmt.Errorf("could not set configuration variables. Err: %v", err))
		os.Exit(1)
	}

	logger := logging.NewLogger(loggerConfiguration)

	logger.Info("Starting Authentication Service...")

}
