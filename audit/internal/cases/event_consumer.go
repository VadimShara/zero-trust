package cases

import "context"

type Message struct {
	Topic string
	Value []byte
}

type EventConsumer interface {
	Subscribe(ctx context.Context, topics []string) (<-chan Message, error)
	Close() error
}
