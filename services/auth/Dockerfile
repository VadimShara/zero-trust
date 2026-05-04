FROM docker.io/library/golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /bin/service ./services/auth/cmd/...

FROM docker.io/library/alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /bin/service /bin/service
COPY services/auth/migrations /app/migrations
ENTRYPOINT ["/bin/service"]
