package ecrscanner

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"kube-ecr-image-scanner/cmd"
	"kube-ecr-image-scanner/internal/pkg/scanner"
)

func Run(cfg *cmd.Config) error {
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

	imageUris, err := scanner.GetContainerImages(kubeClient, cfg.Namespaces, cfg.IncludeNonEcrImages)
	if err != nil {
		return err
	}

	results := scanner.ScanImages(imageUris, cfg.ScanConcurrency, cfg.Timeout, cfg.AWSAccountID)
	// TODO: Parse scan results and generate notification(s)!
	return nil
}
