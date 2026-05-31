# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /usr/src/app

COPY go.mod ./
# Download dependencies
RUN go mod download

COPY main.go ./
# Compile static Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o pdp .

# Final slim stage
FROM alpine:3.19

WORKDIR /app

COPY --from=builder /usr/src/app/pdp .

EXPOSE 8080

CMD ["./pdp"]
