FROM golang:1.20-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /app/rocketguard ./cmd/rocketguard

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/rocketguard /usr/local/bin/rocketguard
USER 1000
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/rocketguard"]