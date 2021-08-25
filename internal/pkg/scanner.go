package pkg

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"k8s.io/klog/v2"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type scanner struct {
	aws         awsConfig
	ecr         ecriface.ECRAPI
	ctx         context.Context
	imageChan   chan string
	resultsChan chan struct{}
	wg          *sync.WaitGroup
}

type awsConfig struct {
	accountId string
	region    string
}

func ScanImages(imageUris []string, concurrency int, timeout time.Duration, accountId string) {
	if len(imageUris) == 0 {
		klog.Info("No images to scan; nothing to do.")
		return
	}
	klog.Infof("Started %d vulnerability scans at %s", len(imageUris), time.Now().Format(time.RFC1123))
	// Put all images into a channel to scan them concurrently
	images := make(chan string, len(imageUris))
	for _, imageUri := range imageUris {
		images <- imageUri
	}

	// Configure cancellation context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	// Configure shutdown signal handler
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChannel
		klog.Infof("Termination signal received, terminating image scanners...")
		cancel()
	}()

	// Configure image scanners and results channel
	results := make(chan struct{}, len(imageUris))
	s := newScanner(&sync.WaitGroup{}, ctx, images, results, accountId)
	s.wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go s.processImages()
	}

	// Close the images channel to signal to goroutines that all images have been queued for processing
	close(images)

	// Wait for image scans to complete and populate the results channel (or for a termination signal to be received)
	s.wg.Wait()

	// TODO: Maybe do this in another function/goroutine? (pkg/exporter? Need to handle results channel differently.)
	// Process all the image scan results
	close(results)
	for result := range results {
		klog.Infof("received result: %v", result)
		// TODO: Process scan results here!
	}

	// Ensure cancel() is called to clean up any remaining context resources
	cancel()
	klog.Infof("All image scans completed.")
	// TODO: return scan results (or error) here!
}

func newScanner(wg *sync.WaitGroup, ctx context.Context, imageChan chan string, resultsChan chan struct{}, accountId string) *scanner {
	s := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			CredentialsChainVerboseErrors: aws.Bool(true),
		},
		SharedConfigState: session.SharedConfigEnable,
	}))
	return &scanner{
		awsConfig{accountId, *s.Config.Region},
		ecr.New(s),
		ctx,
		imageChan,
		resultsChan,
		wg,
	}
}

func (s *scanner) processImages() {
	defer s.wg.Done()
	for {
		select {
		case imageUri, ok := <-s.imageChan:
			if !ok {
				return
			}
			scanImageUri := imageUri
			if isEcrUri, _ := regexp.MatchString(ecrRepoPattern, imageUri); !isEcrUri {
				dst, err := copyImageToECR(s.ctx, s.ecr, imageUri, s.aws.accountId, s.aws.region)
				if err != nil {
					klog.Errorf("Error copying image %s to ECR for scanning: %s", imageUri, err.Error())
					break
				}
				scanImageUri = *dst
			}
			if s.scanImage(imageUri, scanImageUri) {
				s.processScanResults(imageUri, scanImageUri, s.resultsChan)
			}
		case <-s.ctx.Done():
			klog.Info("Received cancellation signal, stopping image processing...")
			return
		}
	}
}

func (s *scanner) scanImage(imageUri, scanImageUri string) bool {
	klog.Infof("Scanning image: %s", imageUri)
	imageTag, repoName, registryId := splitECRAddress(scanImageUri)
	in := &ecr.StartImageScanInput{
		ImageId: &ecr.ImageIdentifier{
			ImageTag: imageTag,
		},
		RegistryId:     registryId,
		RepositoryName: repoName,
	}
	out, err := s.ecr.StartImageScanWithContext(s.ctx, in)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ecr.ErrCodeLimitExceededException:
				klog.Info("Retrieving existing AWS ECR image scan results for %s:%s", repoName, imageTag)
				return true
			case ecr.ErrCodeImageNotFoundException:
				klog.Errorf("Image %s:%s not found", repoName, imageTag)
			default:
				klog.Errorf("Error when scanning repository %s:%s: %s", repoName, imageTag, err.Error())
			}
		}
		return false
	}
	klog.Info("Started AWS ECR image scan on %s:%s: %s", *out.RepositoryName, *out.ImageId.ImageTag, *out.ImageScanStatus.Status)
	return true
}

func (s *scanner) processScanResults(imageUri, scanImageUri string, resultsChan chan struct{}) {
	klog.Infof("Processing scan results for image: %s", imageUri)
	imageTag, repoName, registryId := splitECRAddress(scanImageUri)
	in := &ecr.DescribeImageScanFindingsInput{
		ImageId: &ecr.ImageIdentifier{
			ImageTag: imageTag,
		},
		RegistryId:     registryId,
		RepositoryName: repoName,
	}
	if err := s.ecr.WaitUntilImageScanCompleteWithContext(s.ctx, in); err != nil {
		klog.Errorf("Error while waiting for image scan to complete: %s", err.Error())
	}
	out, _ := s.ecr.DescribeImageScanFindingsWithContext(s.ctx, in)
	for _, finding := range out.ImageScanFindings.Findings {
		klog.Infof("Found vulnerability info for image %s: %v", imageUri, finding)
	}
	// TODO: Return findings through the results channel here!
	resultsChan <- struct{}{}
}

func splitECRAddress(imageUri string) (*string, *string, *string) {
	imageUriParts := strings.Split(imageUri, ":")
	repoParts := strings.SplitN(imageUriParts[0], "/", 2)
	return aws.String(imageUriParts[1]), aws.String(repoParts[1]), aws.String(strings.Split(repoParts[0], ".")[0])
}
