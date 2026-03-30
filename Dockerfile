FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/server ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache wget ca-certificates
COPY --from=builder /app/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
