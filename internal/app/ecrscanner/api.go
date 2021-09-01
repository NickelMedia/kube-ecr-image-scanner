package ecrscanner

import (
	"context"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"kube-ecr-image-scanner/cmd"
	"kube-ecr-image-scanner/internal/pkg/report"
	"kube-ecr-image-scanner/internal/pkg/scanner"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Run(cfg *cmd.Config) error {
	kubeClient, err := getKubeClient(cfg)
	if err != nil {
		return err
	}

	awsAccountId, err := getAwsAccountId(cfg)
	if err != nil {
		return err
	}

	// Create the cancellation context and termination signal handler
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChannel
		klog.Info("Termination signal received, cancelling scan...")
		cancel()
	}()

	// Get a list of all container images running in the given namespaces
	imageUris, err := scanner.GetContainerImages(kubeClient, cfg.Namespaces, cfg.IncludeNonEcrImages)
	if err != nil {
		return err
	}

	// Scan each container image in the list and build a vulnerability report
	results := scanner.ScanImages(ctx, imageUris, cfg.Concurrency, *awsAccountId)
	imageReports := report.Build(ctx, cfg.SeverityThreshold, cfg.Concurrency, results)

	// Export the vulnerability reports using the given exporter
	exp := report.NewExporter(&cfg.ExporterConfig)
	return exp.Export(imageReports)
}

// getKubeClient returns a kubernetes client configured with an in-cluster config, or an external kubeconfig file.
func getKubeClient(cfg *cmd.Config) (*kubernetes.Clientset, error) {
	kubeConfig, err := rest.InClusterConfig()
	if err == rest.ErrNotInCluster {
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", cfg.KubeConfigPath)
	}
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(kubeConfig)
}

// getAwsAccountId returns the AWS Account ID from the EC2 Instance Metadata Service, or from the application config.
func getAwsAccountId(cfg *cmd.Config) (*string, error) {
	svc := ec2metadata.New(session.Must(session.NewSessionWithOptions(session.Options{SharedConfigState: session.SharedConfigEnable})))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	id, err := svc.GetInstanceIdentityDocumentWithContext(ctx)
	if err != nil {
		if cfg.AWSAccountID == "" {
			klog.Errorf("Unable to query EC2 Instance Metadata Service and config.AWSAccountID was not set")
			return nil, err
		}
		id = ec2metadata.EC2InstanceIdentityDocument{AccountID: cfg.AWSAccountID}
	}
	return &id.AccountID, nil
}
