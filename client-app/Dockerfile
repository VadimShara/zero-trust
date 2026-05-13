FROM docker.io/library/golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .
RUN go build -mod=vendor -o /bin/client-app ./client-app/cmd/...

FROM docker.io/library/alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /bin/client-app /bin/client-app
COPY client-app/config/config.yaml /app/config.yaml
ENTRYPOINT ["/bin/client-app"]
