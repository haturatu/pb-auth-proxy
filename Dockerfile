FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/auth-proxy-server ./cmd/server

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /out/auth-proxy-server /app/auth-proxy-server
COPY templates /app/templates

EXPOSE 8080

CMD ["/app/auth-proxy-server"]
