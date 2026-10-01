// Package mail sends the server's transactional emails (currently only
// password reset). Delivery sits behind the Mailer interface so handlers
// and tests never depend on SMTP.
package mail

import (
	"context"
	"log/slog"
)

// Message is one plain-text email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Mailer delivers a Message. Implementations must be safe for concurrent
// use and must honour ctx cancellation/deadline.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// LogMailer is the development fallback used when no SMTP server is
// configured. It never delivers anything. With LogBodies set it writes the
// full message to the log so a developer can follow a reset link; leave
// that off anywhere real users exist, because the body carries a live
// credential.
type LogMailer struct {
	Logger    *slog.Logger
	LogBodies bool
}

func (m *LogMailer) Send(_ context.Context, msg Message) error {
	if m.LogBodies {
		m.Logger.Info("email not delivered (no SMTP configured); dev logging enabled",
			"subject", msg.Subject, "body", msg.Body)
		return nil
	}
	m.Logger.Warn("email not delivered: SMTP is not configured", "subject", msg.Subject)
	return nil
}
