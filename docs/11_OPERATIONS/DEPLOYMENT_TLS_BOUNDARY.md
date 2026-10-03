# Deployment TLS and Forwarded-Header Boundary

## Repository-owned controls

The repository does **not** own public TLS termination. `docker-compose.yml`
publishes no host port for `api-gateway`; it declares only `expose: 80` on the
Compose network. `docker/nginx.conf` listens on port 80 and forwards HTTP to
the application containers. The service Dockerfiles expose container ports,
but the Compose file does not publish those ports on the host.

Therefore the checked-in Compose configuration prevents direct host-port
access to the gateway, but it does not provide TLS. Any container attached to
the Compose network can reach the gateway over HTTP. TLS protection for public
clients depends on the deployment's external ingress and is not enforced or
verified by this repository.

## Required deployment topology

The operator must provide a public ingress that:

1. Owns the public listener and certificate and accepts HTTPS only for
   authenticated API traffic.
2. Terminates TLS before forwarding to `api-gateway:80` over a private,
   access-controlled network.
3. Prevents direct public access to the gateway and application container
   ports, including through alternate host mappings or firewall rules.
4. Restricts network access to the gateway to the intended ingress and
   Compose peers required by the deployment.

The deployment owner must retain ingress configuration and an external
reachability check as evidence. No such ingress configuration or runtime
evidence is included in this repository.

## Forwarded headers

The checked-in nginx configuration does not set `X-Forwarded-Proto`,
`X-Forwarded-Host`, or `X-Forwarded-For`, and the Uvicorn command does not
enable proxy-header trust. The application must not treat caller-supplied
forwarded headers as proof that a request used TLS.

If the deployment later uses forwarded headers, the ingress must remove
client-supplied forwarded-header values and set its own values. The gateway
must accept those values only from a known ingress path, and the application
must trust only explicitly configured proxy addresses. Do not enable
unrestricted forwarded-header trust (such as trusting every source address).

## Acceptance boundary

Repository evidence establishes that Compose has no host-published gateway
port and no in-repository TLS listener. It does not establish the security of
an external ingress. Final deployment acceptance requires independent review
of the actual ingress, host port mappings, firewall/network policy, and
forwarded-header behavior.
