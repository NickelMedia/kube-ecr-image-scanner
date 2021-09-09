package scanner

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"k8s.io/klog/v2"
	"kube-ecr-image-scanner/internal/pkg/cache"
	"regexp"
	"strings"
	"sync"
	"time"
)

type scanner struct {
	aws         awsConfig
	ecr         ecriface.ECRAPI
	ctx         context.Context
	imageChan   chan string
	resultsChan chan *ImageScanResult
	wg          *sync.WaitGroup
}

type awsConfig struct {
	accountId string
	region    string
}

type ImageScanResult struct {
	Image    *string
	Findings *ecr.ImageScanFindings
	Err      error
}

// numArchs is an estimate of the total amount of different architectures that can be supported by a manifest list.
const numArchs int = 10

// ScanImages concurrently scans a list of images for vulnerabilities using AWS ECR.
func ScanImages(ctx context.Context, imageUris []string, concurrency int, accountId string) chan *ImageScanResult {
	if len(imageUris) == 0 {
		klog.Info("No images to scan; nothing to do.")
		return nil
	}
	klog.Infof("Started %d vulnerability scans at %s", len(imageUris), time.Now().Format(time.RFC1123))
	// Put all images into a channel to scan them concurrently
	images := make(chan string, len(imageUris))
	for _, imageUri := range imageUris {
		images <- imageUri
	}

	// Configure image scanners and results channel, ensuring there is enough room in the results channel
	// for per-architecture scan results of multi-arch images
	results := make(chan *ImageScanResult, len(imageUris) * numArchs)
	s := newScanner(&sync.WaitGroup{}, ctx, images, results, accountId)
	s.wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go s.processImages()
	}

	// Close the images channel to signal to goroutines that all images have been queued for processing
	close(images)

	// Wait for image scans to complete and populate the results channel (or for a termination signal to be received)
	s.wg.Wait()

	klog.Infof("All image scans completed.")
	return results
}

// newScanner returns a new scanner for handling image scan requests.
func newScanner(wg *sync.WaitGroup, ctx context.Context, imageChan chan string, resultsChan chan *ImageScanResult, accountId string) *scanner {
	s := session.Must(session.NewSessionWithOptions(session.Options{SharedConfigState: session.SharedConfigEnable}))
	return &scanner{
		awsConfig{accountId, *s.Config.Region},
		ecr.New(s),
		ctx,
		imageChan,
		resultsChan,
		wg,
	}
}

// processImages starts vulnerability scans and retrieves the results for all image URIs in the scanner's image URI
// channel; can safely be called concurrently.
func (s *scanner) processImages() {
	defer s.wg.Done()
	for {
		select {
		// Handle images received from the imageChannel
		case imageUri, ok := <-s.imageChan:
			// End this worker if the channel is closed and there are no more items in the channel
			if !ok {
				return
			}

			// Ensure scans are triggered for every image in a multi-arch manifest list
			if manifestList, err := cache.DetectMultiArchImage(imageUri); err == nil {
				for _, m := range manifestList.Manifests {
					klog.Infof("Detected image within multi-arch manifest %s: %s%s", imageUri, m.Platform.Architecture, m.Platform.Variant)
					imageName := strings.Split(imageUri, ":")[0]
					s.doScan(fmt.Sprintf("%s@%s", imageName, m.Digest), fmt.Sprintf("%s-%s%s", imageUri, m.Platform.Architecture, m.Platform.Variant))
				}
			} else {
				klog.Info(err)
				s.doScan(imageUri, imageUri)
			}
		// Handle Context cancellation
		case <-s.ctx.Done():
			klog.Info("Received cancellation signal, stopping image processing...")
			return
		}
	}
}

// doScan triggers the image scan, and puts the scan results on the results channel for further processing.
func (s *scanner) doScan(imageUri, imageLabel string) {
	// Track the original imageUri and scanned imageUri separately in case the image needs to be copied to ECR
	scanImageUri := imageUri

	// Copy non-ECR images to ECR for scanning
	if isEcrUri, _ := regexp.MatchString(ecrRepoPattern, imageUri); !isEcrUri {
		dst, err := cache.CopyImageToECR(s.ctx, s.ecr, imageUri, s.aws.accountId, s.aws.region)
		if err != nil {
			klog.Errorf("Error copying image %s to ECR for scanning: %s", imageUri, err.Error())
			return
		}
		// Update the imageUri to scan while keeping the original imageUri
		scanImageUri = *dst
	}

	// Put the scan results (or any errors) and imageUri on a channel for further processing
	var findings *ecr.ImageScanFindings
	err := s.scanImage(imageUri, scanImageUri)
	if err == nil {
		findings, err = s.getScanResults(imageUri, scanImageUri)
	}

	s.resultsChan <- &ImageScanResult{
		&imageLabel,
		findings,
		err,
	}
}

// scanImage starts a vulnerability scan for a given image.
func (s *scanner) scanImage(imageUri, scanImageUri string) error {
	klog.Infof("Scanning image: %s", imageUri)
	imageId, repoName, registryId := splitECRAddress(scanImageUri)
	in := &ecr.StartImageScanInput{
		ImageId:        imageId,
		RegistryId:     registryId,
		RepositoryName: repoName,
	}
	var imageTag string
	if imageId.ImageTag != nil {
		imageTag = fmt.Sprintf(":%s", *imageId.ImageTag)
	} else {
		imageTag = fmt.Sprintf("@%s", *imageId.ImageDigest)
	}
	out, err := s.ecr.StartImageScanWithContext(s.ctx, in)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ecr.ErrCodeLimitExceededException:
				klog.Infof("Retrieving existing AWS ECR image scan results for %s%s", *repoName, imageTag)
				return nil
			case ecr.ErrCodeImageNotFoundException:
				klog.Errorf("Image %s%s not found", *repoName, imageTag)
			default:
				klog.Errorf("Error when scanning repository %s%s: %s", *repoName, imageTag, err.Error())
			}
		}
		return err
	}
	klog.Infof("Started AWS ECR image scan on %s%s: %s", *out.RepositoryName, imageTag, *out.ImageScanStatus.Status)
	return nil
}

// getScanResults retrieves the latest image scan results for a given image.
func (s *scanner) getScanResults(imageUri, scanImageUri string) (*ecr.ImageScanFindings, error) {
	klog.Infof("Waiting for scan results for image: %s", imageUri)
	imageId, repoName, registryId := splitECRAddress(scanImageUri)
	in := &ecr.DescribeImageScanFindingsInput{
		ImageId:        imageId,
		RegistryId:     registryId,
		RepositoryName: repoName,
	}
	if err := s.ecr.WaitUntilImageScanCompleteWithContext(s.ctx, in); err != nil {
		klog.Errorf("Error while waiting for image scan on %s to complete: %s", scanImageUri, err.Error())
		return nil, err
	}
	out, err := s.ecr.DescribeImageScanFindingsWithContext(s.ctx, in)
	if err != nil {
		klog.Errorf("Error describing image scan findings for %s: %s", scanImageUri, err.Error())
		return nil, err
	}
	return out.ImageScanFindings, nil
}

// splitECRAddress splits an ECR image URI into <imageIdentifier>, <repositoryName>, <registryAccountId> components.
func splitECRAddress(imageUri string) (*ecr.ImageIdentifier, *string, *string) {
	if strings.Contains(imageUri, "@") {
		imageUriParts := strings.Split(imageUri, "@")
		repoParts := strings.SplitN(imageUriParts[0], "/", 2)
		return &ecr.ImageIdentifier{ImageDigest: aws.String(imageUriParts[1])}, aws.String(repoParts[1]), aws.String(strings.Split(repoParts[0], ".")[0])
	} else {
		imageUriParts := strings.Split(imageUri, ":")
		repoParts := strings.SplitN(imageUriParts[0], "/", 2)
		return &ecr.ImageIdentifier{ImageTag: aws.String(imageUriParts[1])}, aws.String(repoParts[1]), aws.String(strings.Split(repoParts[0], ".")[0])
	}
}
