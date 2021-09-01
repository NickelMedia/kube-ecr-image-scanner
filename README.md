# kube-ecr-image-scanner

## Overview

**kube-ecr-image-scanner** is a tool that lists all container images running on a Kubernetes cluster,
optionally filtered by namespace; then uploads them to AWS ECR, scans each image for vulnerabilities,
and generates a vulnerability report that can be stored for further analysis.

## Motivation

AWS ECR allows users to trigger a manual vulnerability scan, or to scan images automatically on push.
However, it currently doesn't provide a mechanism to re-scan images for vulnerabilities on an interval.
**kube-ecr-image-scanner** allows Kubernetes cluster administrators to automatically scan all the running
images in their cluster for vulnerabilities, ensuring compliance with container security best practices.

## Limitations

AWS ECR only allows scanning a given image once every 24 hours. Your configured scan interval should
take this into account.

## Usage

### Cluster Deployment
[Kustomize](https://kubectl.docs.kubernetes.io/guides/introduction/) manifests are provided in the `deploy` directory;
users can deploy them with kubectl as-is, which will create resources in the `default` namespace:
```
kubectl apply -k https://github.com/NickelMedia/kube-ecr-image-scanner.git/deploy/base
```
Alternatively, users can modify the deployment namespace using an overlay:
```
$ mkdir base
$ cat <<EOF > base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: dev
resources:
- https://github.com/NickelMedia/kube-ecr-image-scanner.git/deploy/base
EOF
$ kubectl apply -k base
$ rm -rf base
```

### Flags

```
Usage: ecrscanner [--aws-account-id AWS-ACCOUNT-ID] [--concurrency CONCURRENCY] [--include-non-ecr-images] [--kube-config-path KUBE-CONFIG-PATH] [--namespaces NAMESPACES] [--severity-threshold SEVERITY-THRESHOLD] [--timeout TIMEOUT] [--format FORMAT] [--slack-channel-id SLACK-CHANNEL-ID] [--slack-token SLACK-TOKEN]
Options:
  --aws-account-id AWS-ACCOUNT-ID
                         AWS Account ID of the registry used to scan images. Required if not running on EC2. [env: AWS_ACCOUNT_ID]
  --concurrency CONCURRENCY, -c CONCURRENCY
                         Number of concurrent images to download/scan. [default: 5, env: CONCURRENCY]
  --include-non-ecr-images
                         Whether non-ECR images should be uploaded to ECR for scanning. [default: true, env: INCLUDE_NON_ECR_IMAGES]
  --kube-config-path KUBE-CONFIG-PATH
                         Path to a kubeconfig file used to access the cluster. Required if not running on Kubernetes. [env: KUBE_CONFIG_PATH]
  --namespaces NAMESPACES
                         Comma-separated list of namespaces to scan. [env: NAMESPACES]
  --severity-threshold SEVERITY-THRESHOLD, -s SEVERITY-THRESHOLD
                         The severity that will trigger a vunerability report. [default: HIGH, env: SEVERITY_THRESHOLD]
  --timeout TIMEOUT      The maximum duration of the scan. [default: 30m, env: TIMEOUT]
  --format FORMAT, -f FORMAT
                         The type of report to export. One of (text, slack). [default: text, env: FORMAT]
  --slack-channel-id SLACK-CHANNEL-ID
                         The Slack Channel ID used to send vulnerability reports. Required if --format=slack. [env: SLACK_CHANNEL_ID]
  --slack-token SLACK-TOKEN
                         The Slack API token used to send Slack messages. Required if --token=slack. [env: SLACK_TOKEN]
  --help, -h             display this help and exit
```

### Permissions

The following AWS IAM permissions are required by **kube-ecr-image-scanner** in order to scan images:

- ecr:DescribeRepositories
- ecr:DescribeImageScanFindings
- ecr:StartImageScan

When using the `--include-non-ecr-images` flag, additional permissions are required in order to store images on
ECR for scanning but can be restricted to a single repository prefix, as shown in the following example IAM role:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowImageScan",
            "Effect": "Allow",
            "Action": [
                "ecr:StartImageScan",
                "ecr:DescribeRepositories",
                "ecr:DescribeImageScanFindings"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowExternalImageCache",
            "Effect": "Allow",
            "Action": [
                "ecr:UploadLayerPart",
                "ecr:PutLifecyclePolicy",
                "ecr:PutImage",
                "ecr:ListImages",
                "ecr:InitiateLayerUpload",
                "ecr:GetRepositoryPolicy",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetAuthorizationToken",
                "ecr:DescribeImages",
                "ecr:CreateRepository",
                "ecr:CompleteLayerUpload",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability"
            ],
            "Resource": "arn:aws:ecr:<<REGION>>:<<AWS_ACCOUNT_ID>>:repository/kube-ecr-image-scanner-cache/*"
        }
    ]
}
```
