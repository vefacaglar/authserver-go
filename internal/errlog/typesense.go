package errlog

import (
	"bytes"
	"context"
	_ "embed"
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

//go:embed application_logs_v1.json
var collectionSchema []byte

// TypesenseSink delivers logs from a bounded queue independently of requests.
type TypesenseSink struct {
	collectionsURL string
	documentsURL   string
	key            string
	local          *slog.Logger
	client         *http.Client
	queue          chan []byte
	done           chan struct{}
	cancel         context.CancelFunc
	mu             sync.Mutex
	closed         bool
	overflow       sync.Once
}

// NewTypesenseSink creates a writer for application_logs_v1. The key needs
// documents:create and, if the collection is missing, collections:create.
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
		collectionsURL: u.JoinPath("collections").String(),
		documentsURL:   u.JoinPath("collections", collection, "documents").String(),
		key:            key, local: local, queue: make(chan []byte, 256), done: make(chan struct{}), cancel: cancel,
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
	status, err := s.post(ctx, s.documentsURL, data)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		if err := s.createCollection(ctx); err != nil {
			return err
		}
		status, err = s.post(ctx, s.documentsURL, data)
		if err != nil {
			return err
		}
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Typesense returned HTTP %d", status)
	}
	return nil
}

func (s *TypesenseSink) createCollection(ctx context.Context) error {
	status, err := s.post(ctx, s.collectionsURL, collectionSchema)
	if err != nil {
		return fmt.Errorf("create Typesense log collection: %w", err)
	}
	switch {
	case status >= 200 && status < 300, status == http.StatusConflict:
		// Another writer may have created the collection after the 404.
		return nil
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return fmt.Errorf("create Typesense log collection: HTTP %d, check collections:create permission for %s", status, collection)
	default:
		return fmt.Errorf("create Typesense log collection: HTTP %d", status)
	}
}

func (s *TypesenseSink) post(ctx context.Context, endpoint string, data []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return 0, errors.New("could not build Typesense request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TYPESENSE-API-KEY", s.key)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, errors.New("could not reach Typesense")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, nil
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10)); err != nil {
		return 0, errors.New("could not read Typesense response")
	}
	return resp.StatusCode, nil
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
