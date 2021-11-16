ARG GOLANG_VERSION=1.17

FROM golang:${GOLANG_VERSION} as builder

WORKDIR /workspace

COPY . .

RUN cd /workspace && go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o main main.go

# Use distroless as minimal base image to package the manager binary
FROM gcr.io/distroless/base:latest-amd64

WORKDIR /

# FIX: this must be changed to the correct name
LABEL org.opencontainers.image.source https://github.com/ydataai/go-template

COPY --from=builder /workspace/main .

ENTRYPOINT ["/main"]
