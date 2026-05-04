# Stage 1: build the Kafka SPI plugin
# Dependencies are pre-downloaded into kafka-listener/libs/ — no internet needed.
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
COPY kafka-listener/pom.xml .
COPY kafka-listener/libs ./libs
COPY kafka-listener/src ./src
RUN mvn package -q -DskipTests

# Stage 2: Keycloak with the SPI plugin and kafka-clients bundled
FROM quay.io/keycloak/keycloak:24.0
# SPI plugin JAR
COPY --from=builder /build/target/keycloak-kafka-listener-1.0.0.jar \
    /opt/keycloak/providers/keycloak-kafka-listener.jar
# kafka-clients must also be in providers/ so Keycloak classloader can find it
COPY kafka-listener/libs/kafka-clients-3.6.2.jar \
    /opt/keycloak/providers/kafka-clients-3.6.2.jar
