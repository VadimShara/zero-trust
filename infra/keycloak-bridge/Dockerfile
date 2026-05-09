FROM docker.io/library/golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -o /keycloak-bridge ./infra/keycloak-bridge/cmd

FROM docker.io/library/alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /keycloak-bridge /keycloak-bridge
ENTRYPOINT ["/keycloak-bridge"]
