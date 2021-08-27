package ecrscanner

import (
	"context"
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
)

func Run(cfg *cmd.Config) error {
	// Configure a kubernetes client using an in-cluster config, or an external kubeconfig file.
	kubeConfig, err := rest.InClusterConfig()
	if err == rest.ErrNotInCluster {
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", cfg.KubeConfigPath)
	}
	if err != nil {
		return err
	}
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}

	// TODO: Get the AWS Account ID from an IAM Instance Profile, and fallback to the input value the same way that KubeConfigPath is handled above! (Then --aws-account-id can be optional.)

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
	results := scanner.ScanImages(ctx, imageUris, cfg.Concurrency, cfg.AWSAccountID)
	imageReports := report.Build(ctx, results, cfg.Concurrency)
	aggregateReport, err := report.Export(imageReports)

	// TODO: Generate report notification! (slack/email/etc.)
	klog.Infof("GENERATED REPORT: %s\n", *aggregateReport)
	return err
}
