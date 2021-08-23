package main

import (
	"github.com/alexflint/go-arg"
	"k8s.io/klog"
	"kube-ecr-image-scanner/cmd"
	"kube-ecr-image-scanner/internal/app/ecrscanner"
)

func main() {
	cfg := cmd.DefaultConfiguration()
	arg.MustParse(cfg)
	if err := ecrscanner.Run(cfg); err != nil {
		klog.Errorf("Error running kube-ecr-image-scanner: %v", err)
	}
	klog.Info("Shutting down...")
}
