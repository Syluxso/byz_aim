package com.nyberg.iam.events;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "byz.kafka.enabled", havingValue = "true", matchIfMissing = true)
public class IamAccessKafkaPublisher {

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    /**
     * Same topic as byz-gateway so Admin live requests / ops SSE see direct IAM hits
     * (login, refresh) without routing browsers through the gateway.
     */
    @Value("${byz.kafka.topics.gateway-access:byz.gateway.access}")
    private String topic;

    /** Best-effort; never fails the HTTP response. */
    public void publishAsync(IamAccessEvent event) {
        try {
            String json = objectMapper.writeValueAsString(event);
            String key = event.requestId() != null ? event.requestId() : event.eventId();
            kafkaTemplate.send(topic, key, json).whenComplete((result, ex) -> {
                if (ex != null) {
                    log.debug("Failed to publish {} requestId={}: {}",
                            event.type(), event.requestId(), ex.toString());
                }
            });
        } catch (JsonProcessingException e) {
            log.debug("Failed to serialize {}: {}", event.type(), e.toString());
        } catch (RuntimeException e) {
            log.debug("Kafka publish skipped for {}: {}", event.type(), e.toString());
        }
    }
}
