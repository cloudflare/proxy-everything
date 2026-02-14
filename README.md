# proxyeverything

It's a TPROXY based docker container sidecar to proxy all traffic from a docker container
to wherever you want.

It leverages HTTP CONNECT to proxy traffic from the container to the host.

# Why do I need this?
This is very useful to do things like "listen to all IP ports that the container connects to".
You can implement your own gateway for docker containers like this.

```
 (your gateway) <--docker bridge device--> [proxy-everything] <-TPROXY-> [user container]
```

# How to build

```
GOOS=linux CGO_ENABLED=0 go build .
```

**Attention**: Do NOT run proxy-everything on your development machine without isolating it in a docker container
or its own network namespace, it will modify your iptables.

You should run it on its own docker container. See "How to use it with Docker".


# How to implement your own gateway for proxy-everything to use

A gateway server should:

1. **Listen on a TCP port** (default: `49121`) accessible from the container's Docker bridge network (typically `172.17.0.1:49121`).

2. **Accept HTTP CONNECT requests**. `proxy-everything` will send requests in this format:
   ```
   CONNECT <destination_host>:<port> HTTP/1.1
   Host: <destination_host>:<port>
   User-Agent: proxy-everything/0.0.1/<source_address>
   Connection: close
   X-Forwarded-For: <source_address>
   X-Proto: tcp
   ```

3. **Parse the destination** from the `Host` header (or request URI) to know where to dial.

4. **Establish a connection to the destination** (the original target the container wanted to reach).

5. **Respond with HTTP status codes**:
   - `2xx` if the connection to the destination succeeded - the tunnel is now established.
   - `400` if the connection to the destination failed (e.g., connection refused).
   - The rest of status codes are treated as errors from the gateway.

6. **Relay data bidirectionally** between the proxy-everything client and the destination after sending the `200 OK` response. The server should:
   - Copy data from the proxy connection to the destination connection.
   - Copy data from the destination connection back to the proxy connection.
   - Handle half-close properly (close write side when read side receives EOF).

See `dummyserver.go` for a simple reference implementation. If you don't want to implement your own, run proxy-everything's reference implementation like:
```
SERVER=1 ./proxy-everything
```

# How to use it with Docker


```bash
export CONTAINER=mycontainer

$ docker build -t proxy-everything:dev .

$ docker run \
		--add-host=host.docker.internal:host-gateway \
		-d --name $(CONTAINER) ubuntu:latest sleep infinity

$ docker run \
		-it --rm --cap-add=NET_ADMIN \
		--network container:$(CONTAINER) \
		--name $(CONTAINER)-proxy proxy-everything:dev


# In another terminal
$ docker exec $(CONTAINER) bash
# You can run commands here to check how proxy-everything works
```

This will make `proxy-everything` to `$(DOCKER_GATEWAY_IP):49121`, `DOCKER_GATEWAY_IP` which usually belongs to `172.17.0.0/16`.
At startup `proxy-everything` will use the default DNS resolver of the container to resolve `host.docker.internal` so it knows
which IP to use to proxy traffic.

When you use `proxy-everything` as a tool that proxies connections to your own host process, you need to make sure
you listen in the right IP, usually this can be accomplished by talking to docker and asking the network gateway of
the container.

Example:
```bash
$ docker network inspect bridge
[
    {
        "Name": "bridge",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": null,
            "Config": [
                {
                    "Subnet": "172.17.0.0/16",
                    "Gateway": "172.17.0.1"
                }
            ]
        },
...
```

By the default by this example,
the TCP address you should be listening in to receive proxy-everything traffic is `172.17.0.1:49121`.

# Philosophy
1. Make it work with docker defaults.
2. Multiplatform.
3. HTTP CONNECT everything.

# Current limitations
1. UDP is out-of-scope currently.
2. Proxying to unix sockets is not implemented yet due to lack of support on MacOS.

# TLDR: How?
We run a sidecar container that joins the container network like in https://gost.run/en/tutorials/redirect/:

```
docker run --add-host=host.docker.internal:host-gateway -it --rm --name iptables-test ubuntu:latest bash

# in another terminal
docker run -it --rm --cap-add=NET_ADMIN --name iptables-test-2 --network container:iptables-test ubuntu:latest bash

apt update && apt install -y iptables iproute2

ip rule add fwmark 1 lookup 100
ip route add local default dev lo table 100

iptables -t mangle -N DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT

iptables -t mangle -N PROXY
iptables -t mangle -A PROXY -p tcp -d 127.0.0.0/8 -j RETURN

# ignore subnet that belongs to the docker interface
iptables -t mangle -A PROXY -p tcp -d 192.168.0.0/16 -j RETURN

iptables -t mangle -A PROXY -p tcp -m mark --mark 100 -j RETURN
iptables -t mangle -A PROXY -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 12345
iptables -t mangle -A PREROUTING -p tcp -j PROXY

# Only for local mode
iptables -t mangle -N PROXY_LOCAL
iptables -t mangle -A PROXY_LOCAL -p tcp -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A PROXY_LOCAL -p tcp -d 255.255.255.255/32 -j RETURN
iptables -t mangle -A PROXY_LOCAL -p tcp -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A PROXY_LOCAL -p tcp -m mark --mark 100 -j RETURN
iptables -t mangle -A PROXY_LOCAL -p tcp -j MARK --set-mark 1
iptables -t mangle -A OUTPUT -p tcp -j PROXY_LOCAL
```

In the proxy, we make use of a syscall to get the original destination IP:
```
if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
    return fmt.Errorf("setsockoptint: %w", err)
}
```

The above can work for both IPv4 and IPv6.



----

Thank you to `upx` contributors and authors, it makes `proxy-everything` live as a very tiny image
that can be pulled and ran very quickly.

https://linux.die.net/man/1/upx
