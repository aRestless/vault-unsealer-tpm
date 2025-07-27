# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

# Install build tools
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go.mod and go.sum to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application for a static build
# The application is placed in the root of the builder stage
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /vault-unsealer-tpm ./cmd

# Stage 2: Create the final image
FROM scratch

# Copy the built binary from the builder stage
COPY --from=builder /vault-unsealer-tpm /vault-unsealer-tpm

# Copy CA certificates from the builder stage to the final image
# This is necessary for the application to be able to communicate with
# the Vault server over TLS.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# The service stores keys in /keys by default, as defined by the
# -store-path flag. We declare this as a volume so that the keys
# can be persisted.
VOLUME /keys

# Set the entrypoint for the container. The application binary is
# executed directly.
ENTRYPOINT ["/vault-unsealer-tpm"]
