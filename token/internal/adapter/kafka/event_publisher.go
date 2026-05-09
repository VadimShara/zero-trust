package kafka

import (
	"context"
	"encoding/json"
	"strings"

	kfk "github.com/segmentio/kafka-go"

	"github.com/zero-trust/zero-trust-auth/token/internal/cases"
)

type Publisher struct {
	writer *kfk.Writer
}

var _ cases.EventPublisher = (*Publisher)(nil)

func NewPublisher(brokers string) *Publisher {
	addrs := strings.Split(brokers, ",")
	for i := range addrs {
		addrs[i] = strings.TrimSpace(addrs[i])
	}
	return &Publisher{
		writer: &kfk.Writer{
			Addr:                   kfk.TCP(addrs...),
			AllowAutoTopicCreation: true,
		},
	}
}

func (p *Publisher) Publish(ctx context.Context, topic string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return p.writer.WriteMessages(ctx, kfk.Message{
		Topic: topic,
		Value: data,
	})
}

func (p *Publisher) Close() error {
	return p.writer.Close()
}
