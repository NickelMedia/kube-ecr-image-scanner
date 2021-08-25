package cmd

import "time"

type Config struct {
	AWSAccountID        string        `arg:"--aws-account-id,env:AWS_ACCOUNT_ID,required"`
	IncludeNonEcrImages bool          `arg:"--include-non-ecr-images,env:INCLUDE_NON_ECR_IMAGES" default:"true"`
	KubeConfigPath      string        `arg:"--kube-config-path,env:KUBE_CONFIG_PATH"`
	Namespaces          []string      `arg:"env"`
	ScanConcurrency     int           `arg:"-c,--scan-concurrency,env:SCAN_CONCURRENCY" default:"5"`
	Timeout             time.Duration `arg:"env" default:"30m"`
}
