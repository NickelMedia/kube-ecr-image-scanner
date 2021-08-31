package cmd

import "time"

type Config struct {
	AWSAccountID        string        `arg:"--aws-account-id,env:AWS_ACCOUNT_ID" help:"AWS Account ID of the registry used to scan images. Required if not running on EC2."`
	Concurrency         int           `arg:"-c,--concurrency,env:CONCURRENCY" default:"5" help:"Number of concurrent images to download/scan."`
	IncludeNonEcrImages bool          `arg:"--include-non-ecr-images,env:INCLUDE_NON_ECR_IMAGES" default:"true" help:"Whether non-ECR images should be uploaded to ECR for scanning."`
	KubeConfigPath      string        `arg:"--kube-config-path,env:KUBE_CONFIG_PATH" help:"Path to a kubeconfig file used to access the cluster. Required if running outside of Kubernetes."`
	Namespaces          []string      `arg:"env" help:"Comma-separated list of namespaces to scan."`
	SeverityThreshold   string        `arg:"-s,--severity-threshold,env:SEVERITY_THRESHOLD" default:"HIGH" help:"The severity that will trigger a vunerability report. One of (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL)"`
	Timeout             time.Duration `arg:"env" default:"30m" help:"The maximum duration of the scan."`
	ExporterConfig
}

type ExporterConfig struct {
	Type  string `arg:"-f,--format,env:FORMAT" default:"text" help:"The type of report to export. One of (text, slack)."`
	SlackConfig
}

type SlackConfig struct {
	ChannelID string `arg:"--slack-channel-id,env:SLACK_CHANNEL_ID" help:"The Slack Channel ID used to send vulnerability reports. Required if --format=slack."`
	Token     string `arg:"--slack-token,env:SLACK_TOKEN" help:"The Slack API token used to send Slack messages. Required if --token=slack."`
}
