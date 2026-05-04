FROM docker.io/library/golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /bin/service ./services/gateway/cmd/...

FROM docker.io/library/alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /bin/service /bin/service
ENTRYPOINT ["/bin/service"]
