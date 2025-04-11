FROM golang:1.24.2-alpine3.21 AS builder

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o ms-stac-proxy main.go

# Use a smaller alpine image for the final container
FROM alpine:3.21

# Add labels for GitHub Container Registry
LABEL org.opencontainers.image.source=https://github.com/Youssef-Harby/ms-stac-proxy
LABEL org.opencontainers.image.description="Microsoft Planetary Computer STAC API Proxy"
LABEL org.opencontainers.image.licenses=MIT

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/ms-stac-proxy .

# Expose the default port
EXPOSE 8080

# Set the entrypoint to run the proxy
ENTRYPOINT ["/app/ms-stac-proxy"]
