// Package errlog projects application diagnostics into the shared log schema.
package errlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"go-authserver/internal/store"
)

// LevelCritical is reserved for failures that require immediate intervention.
const LevelCritical slog.Level = 12

type event struct {
	Timestamp       int64  `json:"timestamp"`
	Service         string `json:"service"`
	Environment     string `json:"environment"`
	Level           string `json:"level"`
	Event           string `json:"event"`
	Message         string `json:"message"`
	RequestID       string `json:"request_id,omitempty"`
	HTTPMethod      string `json:"http_method,omitempty"`
	HTTPRoute       string `json:"http_route,omitempty"`
	HTTPStatus      int    `json:"http_status,omitempty"`
	ResponseCode    string `json:"response_code,omitempty"`
	ResponseMessage string `json:"response_message,omitempty"`
	ErrorType       string `json:"error_type,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
	Source          string `json:"source,omitempty"`
	Stack           string `json:"stack,omitempty"`
}

type handler struct {
	local       slog.Handler
	output      *lockedWriter
	sink        *TypesenseSink
	environment string
}

// NewHandler preserves ordinary local logs and projects warnings, errors,
// and explicitly named info events into the shared schema. Event names,
// messages, and response codes must be developer-authored constants.
func NewHandler(output io.Writer, environment string, sink *TypesenseSink) slog.Handler {
	writer := &lockedWriter{output: output}
	return &handler{local: slog.NewJSONHandler(writer, nil), output: writer, sink: sink, environment: environment}
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.local.Enabled(ctx, level)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copy := *h
	copy.local = h.local.WithAttrs(attrs)
	return &copy
}

func (h *handler) WithGroup(name string) slog.Handler {
	copy := *h
	copy.local = h.local.WithGroup(name)
	return &copy
}

func (h *handler) Handle(ctx context.Context, record slog.Record) error {
	e := event{
		Timestamp: record.Time.UnixMilli(), Service: "authserver-go",
		Environment: h.environment, Message: record.Message,
	}
	switch {
	case record.Level >= LevelCritical:
		e.Level = "critical"
	case record.Level >= slog.LevelError:
		e.Level = "error"
	case record.Level >= slog.LevelWarn:
		e.Level = "warning"
	default:
		e.Level = "info"
	}
	record.Attrs(func(attr slog.Attr) bool {
		switch attr.Key {
		case "event":
			e.Event = attr.Value.String()
		case "status":
			if attr.Value.Kind() == slog.KindInt64 {
				e.HTTPStatus = int(attr.Value.Int64())
			}
		case "route":
			e.HTTPRoute = attr.Value.String()
		case "response_message":
			e.ResponseMessage = attr.Value.String()
		case "response_code":
			e.ResponseCode = attr.Value.String()
		case "error_code":
			e.ErrorCode = attr.Value.String()
		case "err":
			kind, code := errorMetadata(attr.Value.Any())
			e.ErrorType = kind
			if e.ErrorCode == "" {
				e.ErrorCode = code
			}
		case "stack":
			e.Stack, _ = attr.Value.Any().(string)
		}
		return true
	})
	if e.Event == "" {
		if record.Level < slog.LevelWarn {
			return h.local.Handle(ctx, record)
		}
		e.Event = "application_error"
		if record.Level < slog.LevelError {
			e.Event = "application_warning"
		}
	}
	if req, ok := ctx.Value(requestKey{}).(request); ok {
		e.RequestID, e.HTTPMethod = req.id, req.method
		if e.HTTPRoute == "" {
			e.HTTPRoute = req.route()
		}
	}
	if record.PC != 0 {
		frame, _ := runtime.CallersFrames([]uintptr{record.PC}).Next()
		e.Source = fmt.Sprintf("%s:%d", frame.Function, frame.Line)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode log event: %w", err)
	}
	if h.sink != nil {
		h.sink.enqueue(data)
	}
	_, err = h.output.Write(append(data, '\n'))
	return err
}

var sqlState = regexp.MustCompile(`^[0-9A-Z]{5}$`)

func errorMetadata(value any) (kind, code string) {
	err, ok := value.(error)
	if !ok || err == nil {
		return "", ""
	}
	cause := err
	for errors.Unwrap(cause) != nil {
		cause = errors.Unwrap(cause)
	}
	kind = reflect.TypeOf(cause).String()
	var sqlErr interface{ SQLState() string }
	var netErr net.Error
	var smtpErr *textproto.Error
	switch {
	case errors.Is(err, context.Canceled):
		code = "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		code = "deadline_exceeded"
	case errors.Is(err, store.ErrNotFound):
		code = "not_found"
	case errors.Is(err, store.ErrDuplicate):
		code = "duplicate"
	case errors.As(err, &sqlErr) && sqlState.MatchString(sqlErr.SQLState()):
		code = "sqlstate_" + sqlErr.SQLState()
	case errors.As(err, &smtpErr) && smtpErr.Code >= 400 && smtpErr.Code <= 599:
		code = fmt.Sprintf("smtp_%d", smtpErr.Code)
	case errors.Is(err, syscall.ECONNREFUSED):
		code = "connection_refused"
	case errors.Is(err, syscall.ECONNRESET):
		code = "connection_reset"
	case errors.As(err, &netErr) && netErr.Timeout():
		code = "network_timeout"
	}
	return kind, code
}

type requestKey struct{}

type request struct {
	id, method string
	route      func() string
}

// WithRequest attaches safe request metadata. The route must be a router
// template. Its resolver is used only while the handler owns the request.
func WithRequest(ctx context.Context, id, method string, route func() string) context.Context {
	return context.WithValue(ctx, requestKey{}, request{id, method, route})
}

// DetachRequest copies the request metadata for work that outlives the request.
func DetachRequest(ctx context.Context) context.Context {
	base := context.Background()
	if req, ok := ctx.Value(requestKey{}).(request); ok {
		route := req.route()
		return WithRequest(base, req.id, req.method, func() string { return route })
	}
	return base
}

// Stack returns a bounded stack of code locations without panic values or
// function arguments, which can contain request data.
func Stack() string {
	var pcs [32]uintptr
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs[:])])
	var stack strings.Builder
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&stack, "%s:%d\n", frame.Function, frame.Line)
		if !more {
			break
		}
	}
	return stack.String()
}

type lockedWriter struct {
	mu     sync.Mutex
	output io.Writer
}

func (w *lockedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.output.Write(data)
}
