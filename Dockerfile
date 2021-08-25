FROM golang:1.16-stretch AS builder

# Configure go modules and build environment
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

# Cache go modules retrieval
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code necessary to build the application
COPY . .

# Build the application(s)
RUN find /build/cmd -maxdepth 1 -mindepth 1 -type d -printf '%f\n' |\
    xargs -I{} /bin/bash -c "LDFLAGS=\"-X 'main.appName={}' -X 'main.version=`git tag --sort=-version:refname | head -n 1`'\" \
    GODEBUG=netdns=go go build -o {} cmd/{}/main.go"

# Create a /dist folder containing just the files necessary for runtime.
# It will be copied as the root (/) of the output image.
WORKDIR /dist
RUN find /build -maxdepth 1 -mindepth 1 -perm /a+x -exec cp {} /dist \;

# Create the minimal runtime image
FROM alpine:3
RUN apk add ca-certificates
COPY --from=builder /dist /usr/local/bin
ENTRYPOINT ["ecrscanner"]

# Add docker credential helpers so we can pull images from remote repositories and push to AWS ECR
ADD https://amazon-ecr-credential-helper-releases.s3.us-east-2.amazonaws.com/0.5.0/linux-amd64/docker-credential-ecr-login /usr/local/bin/
RUN chmod 755 /usr/local/bin/docker-credential-ecr-login && mkdir /.docker && mkdir /.ecr && chown nobody:nobody /.ecr && echo '{"credsStore":"ecr-login"}' >> /.docker/config.json

# Set the runtime user:group
USER nobody:nobody
WORKDIR /nowhere
