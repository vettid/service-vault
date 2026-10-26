package servicevault_test

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/vettid/service-vault/sdk/go/servicevault"
)

// The member API's use of the client: sign-in from the site, then
// polling (or a webhook) for the outcome. The pin and API key come from
// the application's configuration; in the AWS deployment the pin is the
// value of the SSM parameter the stack exports as TlsPinParameterName.
func Example() {
	c, err := servicevault.New(servicevault.Config{
		BaseURL: "https://service-vault.prod.vettid.internal:8080",
		APIKey:  os.Getenv("SERVICE_VAULT_API_KEY"),
		Pin:     os.Getenv("SERVICE_VAULT_PIN"),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	si, err := c.StartSignIn(ctx, servicevault.SignInRequest{Email: "member@example.org", Source: "203.0.113.7"})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("show the match code %s", si.MatchCode)
	for {
		st, err := c.SignInStatus(ctx, si.ID)
		if err != nil {
			log.Fatal(err)
		}
		if st.Status != servicevault.SignInStatusPending {
			log.Printf("sign-in %s", st.Status)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// Receiving webhooks: verified, decoded, and refused if replayed.
func ExampleReceiver() {
	rc := &servicevault.Receiver{
		Secret: []byte(os.Getenv("SERVICE_VAULT_WEBHOOK_SECRET")),
		Replay: &servicevault.MemoryReplayCache{},
	}
	http.Handle("POST /webhooks/service-vault", rc.Handler(func(ctx context.Context, e servicevault.Event) error {
		switch e := e.(type) {
		case *servicevault.ConnectionPending:
			log.Printf("invite %s: show SAS %s", e.InviteID, e.SAS)
		case *servicevault.ConnectionAdded:
			log.Printf("connection %s added", e.ConnectionID)
		case *servicevault.SignInApproved:
			log.Printf("sign-in %s approved for %s (key changed: %t)", e.SignInID, e.ConnectionID, e.KeyChanged)
		case *servicevault.SignInDenied, *servicevault.SignInExpired:
			log.Printf("sign-in ended: %s", e.EventHeader().Type)
		}
		// nil acknowledges the event (unknown types too); an error answers
		// 500 and the service vault delivers it again.
		return nil
	}))
}
