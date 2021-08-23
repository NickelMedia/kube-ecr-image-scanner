package pkg

import (
	"k8s.io/klog/v2"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func ScanImages(imageUris []string, concurrency int) {
	klog.Infof("Started %d vulnerability scans at %s", len(imageUris), time.Now().Format(time.RFC1123))
	// Put all images into a channel to scan them concurrently
	images := make(chan string, len(imageUris))
	for _, imageUri := range imageUris {
		images <- imageUri
	}

	// Configure shutdown signal handler
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChannel
		klog.Infof("Termination signal received, terminating image scanners...")
		close(images)
	}()

	// Configure image scanners, and wait for all images to be processed (or a termination signal is caught)
	wg := &sync.WaitGroup{}
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go processImages(wg, images)
	}
	wg.Wait()
	klog.Infof("All image scans completed.")

	// TODO: Process and return scan results (or error) here!
}

func processImages(wg *sync.WaitGroup, imageChan chan string ) {
	defer wg.Done()
	for imageUri := range imageChan {
		/*
			TODO: Consider using external code for the scan/process functions, but not
				  https://github.com/nagypeterjob/ecr-scan-lambda since it's too tightly integrated with their logger
				  and while their exporter interface is excellent, their exporters still link out to the ECS dashboard
				  instead of actually parsing the DescribeImageScanFindings response.
				  (Could write a custom exporter using their interface though...)
		*/
		klog.Infof("Scanning image: %s", imageUri)
		scanImage(imageUri)
		klog.Infof("Processing scan results for image: %s", imageUri)
		processScanResults(imageUri)
	}
	klog.Info("All images processed.")
}

func scanImage(imageUri string) {
	// TODO: Trigger scan on AWS and wait for completion here!
}

func processScanResults(imageUri string) {
	// TODO: Call DescribeImageScanFindings and return results (probably to a separate resultsCh?) here!
	// NOTE: Using a separate resultsCh would involve creating a Scanner struct to put these functions on, with a per-Scanner resultsCh (could still be the same channel, just separate references to it)
}
