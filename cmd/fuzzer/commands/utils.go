/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: utils.go
Description: Shared utilities for the Akaylee Fuzzer commands. Provides common
configuration loading, logging setup, and utility functions used across all
command implementations.
*/

package commands

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// LoadConfig loads configuration from files and environment
func LoadConfig() error {
	// Set config file if specified
	if configFile := viper.GetString("config"); configFile != "" {
		viper.SetConfigFile(configFile)
		if err := viper.ReadInConfig(); err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Set environment variable prefix
	viper.SetEnvPrefix("AKAYLEE")
	viper.AutomaticEnv()

	return nil
}

// SetupLogging configures the logging system
func SetupLogging() error {
	logLevel := viper.GetString("log_level")
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	return nil
}
