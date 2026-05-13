package kafka

import (
	"context"
	"sync"

	kfk "github.com/segmentio/kafka-go"

	"github.com/zero-trust/zero-trust-auth/audit/internal/cases"
)

type Consumer struct {
	brokers []string
	groupID string

	mu      sync.Mutex
	readers []*kfk.Reader
}

var _ cases.EventConsumer = (*Consumer)(nil)

func NewConsumer(brokers []string, groupID string) *Consumer {
	return &Consumer{brokers: brokers, groupID: groupID}
}

func (c *Consumer) Subscribe(ctx context.Context, topics []string) (<-chan cases.Message, error) {
	ch := make(chan cases.Message, 256)

	var wg sync.WaitGroup
	for _, topic := range topics {
		r := kfk.NewReader(kfk.ReaderConfig{
			Brokers:  c.brokers,
			Topic:    topic,
			GroupID:  c.groupID,
			MaxBytes: 10 << 20,
		})
		c.mu.Lock()
		c.readers = append(c.readers, r)
		c.mu.Unlock()

		wg.Add(1)
		go func(reader *kfk.Reader) {
			defer wg.Done()
			for {
				msg, err := reader.ReadMessage(ctx)
				if err != nil {
					return
				}
				select {
				case ch <- cases.Message{Topic: msg.Topic, Value: msg.Value}:
				case <-ctx.Done():
					return
				}
			}
		}(r)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch, nil
}

func (c *Consumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.readers {
		_ = r.Close()
	}
	c.readers = nil
	return nil
}
