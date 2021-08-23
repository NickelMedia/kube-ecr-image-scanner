package cmd

import "time"

type Config struct {
	IncludeNonEcrImages bool          `arg:"--include-non-ecr-images,env:INCLUDE_NON_ECR_IMAGES"`
	KubeConfigPath      string        `arg:"--kube-config-path,env:KUBE_CONFIG_PATH"`
	Namespaces          []string      `arg:"env"`
	ScanConcurrency     int           `arg:"-c,--scan-concurrency,env:SCAN_CONCURRENCY"`
	Timeout             time.Duration `arg:"env"`
}

func DefaultConfiguration() *Config {
	return &Config{
		IncludeNonEcrImages: true,
		KubeConfigPath:      "",
		Namespaces:          []string{""}, // The empty string is used to list pods from all namespaces
		ScanConcurrency:     5,
		Timeout:             time.Hour,
	}
}
