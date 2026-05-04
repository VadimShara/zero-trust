package com.zerotrust.keycloak;

import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;

public class KafkaEventListenerProvider implements EventListenerProvider {

    private final Producer<String, String> producer;
    private final String topic;

    public KafkaEventListenerProvider(Producer<String, String> producer, String topic) {
        this.producer = producer;
        this.topic = topic;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() != EventType.LOGIN && event.getType() != EventType.LOGIN_ERROR) {
            return;
        }
        String payload = toJson(event);
        String key = event.getUserId() != null ? event.getUserId() : event.getSessionId();
        producer.send(new ProducerRecord<>(topic, key, payload));
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // not needed
    }

    @Override
    public void close() {}

    private String toJson(Event event) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"type\":\"").append(event.getType()).append("\"");
        sb.append(",\"time\":").append(event.getTime());
        if (event.getUserId() != null)
            sb.append(",\"userId\":\"").append(event.getUserId()).append("\"");
        if (event.getClientId() != null)
            sb.append(",\"clientId\":\"").append(event.getClientId()).append("\"");
        if (event.getError() != null)
            sb.append(",\"error\":\"").append(event.getError()).append("\"");
        if (event.getIpAddress() != null)
            sb.append(",\"ipAddress\":\"").append(event.getIpAddress()).append("\"");
        sb.append("}");
        return sb.toString();
    }
}
