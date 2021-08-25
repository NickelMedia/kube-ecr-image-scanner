package pkg

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"k8s.io/klog/v2"
	"strings"
)

func copyImageToECR(ctx context.Context, client ecriface.ECRAPI, imageUri, accountId, region string) (*string, error) {
	klog.Infof("Pulling image from non-ECR source: %s", imageUri)
	img, err := crane.Pull(imageUri, crane.WithAuthFromKeychain(authn.DefaultKeychain), crane.WithContext(ctx))
	if err != nil {
		klog.Errorf("Unable to pull image from %s: %s", imageUri, err.Error())
		return nil, err
	}
	imageParts := strings.Split(strings.Split(imageUri, "/")[strings.Count(imageUri, "/")], ":")
	imageName, imageTag := imageParts[0], imageParts[1]
	cacheRepo := fmt.Sprintf("kube-ecr-image-scanner-cache/%s", imageName)
	if err := createCacheRepository(ctx, client, cacheRepo); err != nil {
		klog.Errorf("Unable to create cache repository on AWS ECR: %s", err.Error())
		return nil, err
	}
	dst := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", accountId, region, cacheRepo, imageTag)
	klog.Infof("Pushing image to ECR: %s", dst)
	err = crane.Push(img, dst, crane.WithAuthFromKeychain(authn.DefaultKeychain), crane.WithContext(ctx))
	if err != nil {
		klog.Errorf("Unable to push image to %s: %s", dst, err.Error())
		return nil, err
	}
	return &dst, nil
}


func createCacheRepository(ctx context.Context, client ecriface.ECRAPI, cacheRepoName string) error {
	klog.Info("Creating cache repository %s...", cacheRepoName)
	in := &ecr.CreateRepositoryInput{RepositoryName: aws.String(cacheRepoName)}
	_, err := client.CreateRepositoryWithContext(ctx, in)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ecr.ErrCodeRepositoryAlreadyExistsException:
				klog.Info("Cache repository %s already exists", cacheRepoName)
				return nil
			}
		}
	}
	return err
}
