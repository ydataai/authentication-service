ARG GOLANG_VERSION=1.20

FROM golang:${GOLANG_VERSION} as builder

WORKDIR /workspace

COPY . .

RUN cd /workspace && go mod download

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o main -a cmd/main.go

# Use distroless as minimal base image to package the manager binary
FROM gcr.io/distroless/static-debian11:nonroot

WORKDIR /

LABEL org.opencontainers.image.source https://github.com/ydataai/authentication-service

COPY --from=builder /workspace/main .

ENTRYPOINT ["/main"]
