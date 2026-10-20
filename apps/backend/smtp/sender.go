package smtp

import (
	"context"
	"embed"
	"fmt"
	"text/template"
	"time"

	"github.com/tidwall/gjson"
	"github.com/valyala/bytebufferpool"

	"github.com/volodymyr-pavlov/go-vault-webauthn-ollama/apps/backend/es"
)

var _ es.Writer[es.Message] = &Sender{}

//go:embed templates/*.txt
var templateFiles embed.FS

//go:embed templates/subjects.json
var subjectsFile []byte

// messageKind describes one kind of message: the op that asks for it, the key of its template and subject, and whether it
// needs a token. A key is the name of the template file without its extension. It is also the key of the subject in the
// subjects file.
type messageKind struct {
	op         es.Op
	key        string
	needsToken bool
}

// messageKinds lists the kinds of message in the order in which [Sender.WriteOne] matches them. If an op names several, the
// first wins.
var messageKinds = []messageKind{
	{
		op:         es.SendRegistryToken,
		key:        "registry_token",
		needsToken: true,
	},
	{
		op:  es.SendRegistryTaken,
		key: "registry_taken",
	},
	{
		op:  es.SendPasskeyAdded,
		key: "passkey_added",
	},
	{
		op:  es.SendPasskeyRemoved,
		key: "passkey_removed",
	},
	{
		op:  es.SendPasskeyDisabled,
		key: "passkey_disabled",
	},
	{
		op:  es.SendTOTPAdded,
		key: "totp_added",
	},
	{
		op:  es.SendTOTPRemoved,
		key: "totp_removed",
	},
	{
		op:  es.SendRecoveryIssued,
		key: "recovery_issued",
	},
	{
		op:  es.SendRecoveryUsed,
		key: "recovery_used",
	},
	{
		op:         es.SendRecoveryRequested,
		key:        "recovery_requested",
		needsToken: true,
	},
	{
		op:         es.SendRecoveryGrant,
		key:        "recovery_grant",
		needsToken: true,
	},
	{
		op:  es.SendLoginRefused,
		key: "login_refused",
	},
	{
		op:  es.SendAccountDeleted,
		key: "account_deleted",
	},
}

// templateBody is the data that the message templates use.
type templateBody struct {
	Name  string
	Token string
	TTL   time.Duration
}

// Sender writes the messages about an account from the embedded templates and sends them by mail. It implements
// [es.Writer] of [es.Message]. [NewSender] builds it.
type Sender struct {
	client    *Client
	templates map[string]*template.Template
	subjects  map[string]string
}

// NewSender returns a [Sender] that mails through client. It parses the templates and the subjects.
//
// It returns an error wrapping [ErrNoTemplate] if a message has no template or no subject. It returns another error if
// a template cannot be parsed.
func NewSender(client *Client) (*Sender, error) {
	sender := &Sender{
		client:    client,
		templates: map[string]*template.Template{},
		subjects:  map[string]string{},
	}

	if !gjson.ValidBytes(subjectsFile) {
		return nil, fmt.Errorf("read the subjects: %w", ErrNoTemplate)
	}

	subjects := gjson.ParseBytes(subjectsFile)
	for _, kind := range messageKinds {
		key := kind.key

		subject := subjects.Get(key).String()
		if subject == "" {
			return nil, fmt.Errorf("%s: %w", key, ErrNoTemplate)
		}

		text, err := templateFiles.ReadFile("templates/" + key + ".txt")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, ErrNoTemplate)
		}

		parsed, err := template.New(key).Parse(string(text))
		if err != nil {
			return nil, fmt.Errorf("parse the template %s: %w", key, err)
		}

		sender.subjects[key] = subject
		sender.templates[key] = parsed
	}

	return sender, nil
}

// WriteOne implements [es.Writer]. With [es.WriteCreate], it sends the message that op names to the Email of item.
//
// It returns [es.ErrNoArguments] if op does not create a message or does not name one. It returns [ErrNoRecipient] if
// the item has no usable address, and [ErrNoToken] if a message that carries a token has none. It returns another error
// if the message cannot be rendered or sent.
func (s *Sender) WriteOne(ctx context.Context, item es.Message, op es.Op) (es.Message, error) {
	if !es.IsCreate(op) {
		return item, es.ErrNoArguments
	}

	kind, ok := messageFor(op)
	if !ok {
		return item, es.ErrNoArguments
	}

	if kind.needsToken && item.Token == "" {
		return item, ErrNoToken
	}

	key := kind.key

	text := bytebufferpool.Get()
	defer bytebufferpool.Put(text)

	err := s.templates[key].Execute(text, templateBody{
		Name:  item.Name,
		Token: item.Token,
		TTL:   item.TTL,
	})
	if err != nil {
		return item, fmt.Errorf("render the template: %w", err)
	}

	if err := s.client.SendMessage(ctx, item.Email, s.subjects[key], text.String()); err != nil {
		return item, fmt.Errorf("send the message: %w", err)
	}

	return item, nil
}

// messageFor returns the first kind of message that op names.
func messageFor(op es.Op) (messageKind, bool) {
	for _, kind := range messageKinds {
		if op&kind.op != 0 {
			return kind, true
		}
	}

	return messageKind{}, false
}
