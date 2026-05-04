FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /keycloak-bridge ./services/keycloak-bridge/cmd

FROM alpine:3.19
COPY --from=builder /keycloak-bridge /keycloak-bridge
ENTRYPOINT ["/keycloak-bridge"]
