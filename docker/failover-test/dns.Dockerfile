# Tiny authoritative-ish DNS for the fail-over test: serves the SRV record that
# advertises the CMIS nodes (config injected via the dnsmasq.conf mount).
FROM alpine:3.20
RUN apk add --no-cache dnsmasq
ENTRYPOINT ["dnsmasq", "--keep-in-foreground", "--log-queries", "--no-resolv", "--conf-file=/etc/dnsmasq.conf"]
