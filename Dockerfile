FROM golang:1.19-alpine AS builder

WORKDIR /src

COPY go.* ./

RUN go mod download -x

COPY *.go ./

RUN go build -o trivy-reporter ./... 

FROM alpine:3.16

COPY --from=builder /src/trivy-reporter /
COPY *.tpl /

ENTRYPOINT ["/trivy-reporter"]
