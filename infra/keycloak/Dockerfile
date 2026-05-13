FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
COPY kafka-listener/pom.xml .
COPY kafka-listener/libs ./libs
COPY kafka-listener/src ./src
RUN mvn package -q -DskipTests

FROM quay.io/keycloak/keycloak:24.0

COPY --from=builder /build/target/keycloak-kafka-listener-1.0.0.jar \
    /opt/keycloak/providers/keycloak-kafka-listener.jar

COPY kafka-listener/libs/kafka-clients-3.6.2.jar \
    /opt/keycloak/providers/kafka-clients-3.6.2.jar
