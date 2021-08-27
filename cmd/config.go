package cmd

import "time"

type Config struct {
	AWSAccountID        string        `arg:"--aws-account-id,env:AWS_ACCOUNT_ID,required"`
	Concurrency         int           `arg:"-c,--concurrency,env:CONCURRENCY" default:"5"`
	IncludeNonEcrImages bool          `arg:"--include-non-ecr-images,env:INCLUDE_NON_ECR_IMAGES" default:"true"`
	KubeConfigPath      string        `arg:"--kube-config-path,env:KUBE_CONFIG_PATH"`
	Namespaces          []string      `arg:"env"`
	SeverityThreshold   string        `arg:"-s,--severity-threshold,env:SEVERITY_THRESHOLD" default:"HIGH"`
	Timeout             time.Duration `arg:"env" default:"30m"`
}
