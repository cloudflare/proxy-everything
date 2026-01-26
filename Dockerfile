FROM debian:bookworm

RUN apt-get update && apt install -y iptables iproute2
COPY ./proxy-everything /proxy-everything
RUN chmod +x /proxy-everything

ENTRYPOINT ["/proxy-everything"]

