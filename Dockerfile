# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install git for go mod
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the Go binary statically
RUN CGO_ENABLED=0 GOOS=linux go build -o clamav-rest ./cmd/clamav-rest

# Final stage: distroless
FROM gcr.io/distroless/static-debian12

USER nonroot:nonroot

COPY --from=builder /app/clamav-rest /clamav-rest

EXPOSE 8080

ENTRYPOINT ["/clamav-rest"]