FROM golang:1.25-bookworm AS builder

WORKDIR /app
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -o proxy-everything .

FROM debian:bookworm

RUN apt-get update && apt install -y iptables iproute2
COPY --from=builder /app/proxy-everything /proxy-everything
RUN chmod +x /proxy-everything

ENTRYPOINT ["/proxy-everything"]

