package mail

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildMessage(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	raw, err := buildMessage("Auth <no-reply@example.com>", "alice@example.org",
		Message{Subject: "Reset your password", Body: "Hello — link: https://x/y?token=abc\n"}, now)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		"From: \"Auth\" <no-reply@example.com>\r\n",
		"To: alice@example.org\r\n",
		"Subject: Reset your password\r\n",
		"Date: Fri, 02 Oct 2026 12:00:00 +0000\r\n",
		"Content-Transfer-Encoding: quoted-printable\r\n",
		"https://x/y?token=3Dabc", // quoted-printable escapes '='
	} {
		if !strings.Contains(s, want) {
			t.Errorf("message missing %q\n%s", want, s)
		}
	}
	if !strings.Contains(s, "Message-ID: <") || !strings.Contains(s, "@example.com>") {
		t.Error("Message-ID missing or not on the sender's domain")
	}
}

func TestBuildMessage_RejectsHeaderInjection(t *testing.T) {
	now := time.Unix(1700000000, 0)
	if _, err := buildMessage("no-reply@example.com", "a@example.org", Message{Subject: "hi\r\nBcc: evil@example.net"}, now); err == nil {
		t.Error("subject with CRLF accepted")
	}
	if _, err := parseAddress("a@example.org\r\nBcc: evil@example.net"); err == nil {
		t.Error("address with CRLF accepted")
	}
	if _, err := parseAddress("not an address"); err == nil {
		t.Error("garbage address accepted")
	}
}

func TestNewSMTPMailer_Validation(t *testing.T) {
	now := time.Now
	if _, err := NewSMTPMailer(SMTPConfig{From: "a@example.com"}, now); err == nil {
		t.Error("missing host accepted")
	}
	if _, err := NewSMTPMailer(SMTPConfig{Host: "smtp.example.com", From: "nope"}, now); err == nil {
		t.Error("invalid from accepted")
	}
	m, err := NewSMTPMailer(SMTPConfig{Host: "smtp.example.com", From: "a@example.com"}, now)
	if err != nil || m.cfg.Port != "587" {
		t.Errorf("defaults: port=%q err=%v", m.cfg.Port, err)
	}
}

// fakeSMTP is a minimal plaintext SMTP server that records one message.
func fakeSMTP(t *testing.T) (port string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		say := func(s string) { conn.Write([]byte(s + "\r\n")) }
		say("220 fake ESMTP")
		var transcript strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					say("250 queued")
					continue
				}
				transcript.WriteString(line + "\n")
				continue
			}
			switch cmd := strings.ToUpper(line); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"):
				transcript.WriteString(line + "\n")
				say("250 ok")
			case cmd == "DATA":
				inData = true
				say("354 go ahead")
			case cmd == "QUIT":
				say("221 bye")
				got <- transcript.String()
				return
			default:
				say("250 ok")
			}
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, got
}

func TestSMTPMailer_Send(t *testing.T) {
	port, got := fakeSMTP(t)
	m, err := NewSMTPMailer(SMTPConfig{Host: "127.0.0.1", Port: port, From: "Auth <no-reply@example.com>"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), Message{To: "alice@example.org", Subject: "Hi", Body: "body text"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case tr := <-got:
		for _, want := range []string{"MAIL FROM:<no-reply@example.com>", "RCPT TO:<alice@example.org>", "Subject: Hi", "body text"} {
			if !strings.Contains(tr, want) {
				t.Errorf("server transcript missing %q\n%s", want, tr)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake server saw no complete message")
	}
}

func TestSMTPMailer_SendHonoursContextAndBadRecipient(t *testing.T) {
	m, _ := NewSMTPMailer(SMTPConfig{Host: "127.0.0.1", Port: "1", From: "a@example.com", Timeout: time.Second}, time.Now)
	if err := m.Send(context.Background(), Message{To: "bad address", Subject: "x", Body: "y"}); err == nil {
		t.Error("bad recipient accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Send(ctx, Message{To: "a@example.org", Subject: "x", Body: "y"}); err == nil {
		t.Error("cancelled context did not abort Send")
	}
}
