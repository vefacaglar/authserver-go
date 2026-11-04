package errlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const collection = "application_logs_v1"

// TypesenseSink delivers logs from a bounded queue independently of requests.
type TypesenseSink struct {
	endpoint string
	key      string
	local    *slog.Logger
	client   *http.Client
	queue    chan []byte
	done     chan struct{}
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	overflow sync.Once
}

// NewTypesenseSink creates a writer for an existing application_logs_v1
// collection. The API key only needs documents:create on that collection.
func NewTypesenseSink(baseURL, key string, local *slog.Logger) (*TypesenseSink, error) {
	if baseURL == "" && key == "" {
		return nil, nil
	}
	if key == "" {
		return nil, errors.New("AUTH_LOG_TYPESENSE_API_KEY is required when log export is configured")
	}
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Hostname() == "" || u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("AUTH_LOG_TYPESENSE_URL must be an HTTP or HTTPS URL without credentials, query, or fragment")
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &TypesenseSink{
		endpoint: u.JoinPath("collections", collection, "documents").String(),
		key:      key, local: local, queue: make(chan []byte, 256), done: make(chan struct{}), cancel: cancel,
		client: &http.Client{
			Timeout:       2 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	go s.run(ctx)
	return s, nil
}

func (s *TypesenseSink) enqueue(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.queue <- data:
	default:
		s.overflow.Do(func() { s.local.Warn("Typesense log queue full; dropping remote events") })
	}
}

func (s *TypesenseSink) run(ctx context.Context) {
	defer close(s.done)
	var failed bool
	for data := range s.queue {
		if ctx.Err() != nil {
			return
		}
		if err := s.send(ctx, data); err != nil {
			if !failed {
				s.local.Warn("Typesense log delivery failed; events remain on stdout", "reason", err.Error())
			}
			failed = true
		} else if failed {
			s.local.Info("Typesense log delivery resumed")
			failed = false
		}
	}
}

func (s *TypesenseSink) send(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(data))
	if err != nil {
		return errors.New("could not build log request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TYPESENSE-API-KEY", s.key)
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.New("could not reach Typesense")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Typesense returned HTTP %d", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10)); err != nil {
		return errors.New("could not read Typesense response")
	}
	return nil
}

// Close drains pending events within ctx's deadline and cancels pending I/O
// if that deadline is exceeded.
func (s *TypesenseSink) Close(ctx context.Context) {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
	case <-ctx.Done():
		s.local.Warn("Typesense log flush interrupted")
	}
	s.cancel()
}
