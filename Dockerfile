FROM golang:1.16-stretch AS builder

# Configure go modules and build environment
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

# Cache modules retrieval
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code necessary to build the application
COPY . .

# Build the application
RUN LDFLAGS="-X 'main.appName=`basename $(git rev-parse --show-toplevel)`' -X 'main.version=`git tag --sort=-version:refname | head -n 1`'" \
    GODEBUG=netdns=go go build -o main cmd/*/main.go

# Create a /dist folder containing just the files necessary for runtime.
# It will be copied as the root (/) of the output image.
WORKDIR /dist
RUN find /build -perm /a+x -exec cp {} /dist \;

## Create the minimal runtime image
FROM alpine:3
RUN apk add ca-certificates
COPY --from=builder /dist /
ENTRYPOINT ["/main"]
EXPOSE 8080
