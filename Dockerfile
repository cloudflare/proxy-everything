FROM golang:1.25-bookworm AS builder

WORKDIR /app
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w -buildid=" -tags=nethttpomithttp2 -trimpath -o proxy-everything .

FROM alpine:3.21 AS compressor
RUN apk add --no-cache upx
COPY --from=builder /app/proxy-everything /proxy-everything
RUN upx --best /proxy-everything

FROM alpine:3.21
RUN apk add --no-cache iptables ip6tables iproute2
COPY --from=compressor /proxy-everything /proxy-everything
ENTRYPOINT ["/proxy-everything"]
