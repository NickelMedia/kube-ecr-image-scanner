package main

import (
	"github.com/alexflint/go-arg"
	"k8s.io/klog"
	"kube-ecr-image-scanner/cmd"
	"kube-ecr-image-scanner/internal/app/ecrscanner"
)

var appName = "kube-ecr-image-scanner"
var version = "0.0.1-alpha.0"

func main() {
	klog.Infof("Starting %s:%s", appName, version)
	cfg := &cmd.Config{}
	arg.MustParse(cfg)
	if err := ecrscanner.Run(cfg); err != nil {
		klog.Errorf("Error running %s: %v", appName, err)
	}
	klog.Info("Shutting down...")
}
