package kafka

import (
	"context"
	"sync"

	kfk "github.com/segmentio/kafka-go"

	"github.com/zero-trust/zero-trust-auth/audit/internal/cases"
)

// Consumer implements cases.EventConsumer.
// It creates one kafka.Reader per topic and fans all messages into a single channel.
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

// Subscribe starts one goroutine per topic. Messages are fanned into the returned
// channel. The channel is closed when all goroutines have exited (context cancelled
// or Close called).
func (c *Consumer) Subscribe(ctx context.Context, topics []string) (<-chan cases.Message, error) {
	ch := make(chan cases.Message, 256)

	var wg sync.WaitGroup
	for _, topic := range topics {
		r := kfk.NewReader(kfk.ReaderConfig{
			Brokers:  c.brokers,
			Topic:    topic,
			GroupID:  c.groupID,
			MaxBytes: 10 << 20, // 10 MiB
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
					// context cancelled or reader closed — normal shutdown
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

	// Close channel once all readers have exited so range-loops terminate.
	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch, nil
}

// Close closes all underlying Kafka readers, unblocking any in-flight ReadMessage calls.
func (c *Consumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.readers {
		_ = r.Close()
	}
	c.readers = nil
	return nil
}
