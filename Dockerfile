# Multi-stage build for Tidegate
# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo docker)" \
    -o /tidegate ./cmd/tidegate

# Runtime stage — minimal image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /tidegate /usr/local/bin/tidegate

# Config and data directories
RUN mkdir -p /etc/tidegate /var/lib/tidegate

# Default config
ENV TIDEGATE_CONFIG_DIR=/etc/tidegate
ENV TIDEGATE_DATA_DIR=/var/lib/tidegate

EXPOSE 8842

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8842/health || exit 1

ENTRYPOINT ["tidegate"]
CMD ["start"]