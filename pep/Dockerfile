# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /usr/src/app

COPY go.mod ./

COPY main.go ./
# Compile static Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o pep .

# Final stage
FROM alpine:3.19

WORKDIR /app

COPY --from=builder /usr/src/app/pep .

EXPOSE 443

CMD ["./pep"]
