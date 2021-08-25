package scanner

import (
	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"regexp"
	"time"
)

const ecrRepoPattern = "^public.ecr.aws.*|.*\\.dkr\\.ecr\\."

// GetContainerImages returns a list of container images in Pods currently running on the Kubernetes cluster.
func GetContainerImages(kubeClient *kubernetes.Clientset, namespaces []string, includeNonEcrImages bool) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Get a list of all unique images running in the selected namespaces
	imageUris := make(map[string]struct{})
	for _, namespace := range namespaces {
		podList, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, pod := range podList.Items {
			containers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
			for _, container := range containers {
				if includeNonEcrImages {
					imageUris[container.Image] = struct{}{}
				} else if match, _ := regexp.MatchString(ecrRepoPattern, container.Image); match {
					imageUris[container.Image] = struct{}{}
				}
			}
		}
	}

	keys := make([]string, len(imageUris))
	i := 0
	for k := range imageUris {
		keys[i] = k
		i++
	}
	return keys, nil
}
