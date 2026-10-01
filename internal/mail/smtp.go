package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SMTPConfig describes the outgoing mail server.
type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	// From is the sender address, e.g. "Auth <no-reply@example.com>".
	From string
	// Timeout bounds dial plus the whole SMTP dialogue. Zero means 15s.
	Timeout time.Duration
}

// SMTPMailer sends mail over SMTP. Port 465 uses implicit TLS; any other
// port uses STARTTLS when the server offers it. Credentials are only ever
// sent over TLS (net/smtp refuses PLAIN auth on an unencrypted link to a
// non-local host).
type SMTPMailer struct {
	cfg SMTPConfig
	now func() time.Time
}

// NewSMTPMailer validates cfg. now supplies the Date header.
func NewSMTPMailer(cfg SMTPConfig, now func() time.Time) (*SMTPMailer, error) {
	if cfg.Host == "" {
		return nil, errors.New("smtp: host is required")
	}
	if cfg.Port == "" {
		cfg.Port = "587"
	}
	if _, err := parseAddress(cfg.From); err != nil {
		return nil, fmt.Errorf("smtp: invalid from address: %w", err)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &SMTPMailer{cfg: cfg, now: now}, nil
}

func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	to, err := parseAddress(msg.To)
	if err != nil {
		return fmt.Errorf("smtp: invalid recipient: %w", err)
	}
	from, _ := parseAddress(m.cfg.From)
	raw, err := buildMessage(m.cfg.From, to, msg, m.now())
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(m.cfg.Host, m.cfg.Port)
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()

	d := net.Dialer{}
	var conn net.Conn
	if m.cfg.Port == "465" {
		td := tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}}
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: dial: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp: handshake: %w", err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok && m.cfg.Port != "465" {
		if err := c.StartTLS(&tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}
	if m.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("smtp: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: finish body: %w", err)
	}
	return c.Quit()
}

// parseAddress returns the bare address of a single RFC 5322 mailbox and
// rejects anything containing line breaks (header injection).
func parseAddress(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n") {
		return "", errors.New("address contains a line break")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}
	return a.Address, nil
}

// buildMessage renders the RFC 5322 message. fromHeader is the configured
// From value (display name allowed); to is a validated bare address.
func buildMessage(fromHeader, to string, msg Message, now time.Time) ([]byte, error) {
	if strings.ContainsAny(msg.Subject, "\r\n") {
		return nil, errors.New("smtp: subject contains a line break")
	}
	from, err := mail.ParseAddress(fromHeader)
	if err != nil {
		return nil, fmt.Errorf("smtp: invalid from address: %w", err)
	}
	domain := "localhost"
	if i := strings.LastIndex(from.Address, "@"); i >= 0 {
		domain = from.Address[i+1:]
	}

	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from.String())
	h("To", to)
	h("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+uuid.NewString()+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Content-Type", `text/plain; charset="utf-8"`)
	h("Content-Transfer-Encoding", "quoted-printable")
	b.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(msg.Body, "\r\n", "\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
