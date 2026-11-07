package service

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lejianwen/rustdesk-api/v2/config"
	"github.com/lejianwen/rustdesk-api/v2/model"
)

// The dispatcher reads the "cb" claim from the second dot-separated segment.
func TestKozyStateCarriesDispatcherOrigin(t *testing.T) {
	Config = &config.Config{}
	Config.Rustdesk.ApiServer = "https://rustdesk.kozyops.com/"
	if got := kozyState("plain"); got != "plain" {
		t.Fatalf("without KOZY_OAUTH_REDIRECT_URL the state must be upstream's, got %q", got)
	}
	t.Setenv("KOZY_OAUTH_REDIRECT_URL", "https://oauth.kozyops.com/callback")
	parts := strings.Split(kozyState("plain"), ".")
	if len(parts) < 2 {
		t.Fatalf("state has %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]string
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["cb"] != "https://rustdesk.kozyops.com" || len(claims["n"]) < 40 {
		t.Fatalf("claims %v", claims)
	}
}

func TestKozyCheckDomain(t *testing.T) {
	t.Setenv("KOZY_ALLOWED_EMAIL_DOMAIN", "kozyops.com")
	ok := &model.OidcUser{OauthUserBase: model.OauthUserBase{Email: "Tech@KozyOps.com"}, VerifiedEmail: true, Hd: "kozyops.com"}
	if err := kozyCheckDomain(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []*model.OidcUser{
		{OauthUserBase: model.OauthUserBase{Email: "tech@kozyops.com"}, VerifiedEmail: false, Hd: "kozyops.com"},
		{OauthUserBase: model.OauthUserBase{Email: "tech@kozyops.com"}, VerifiedEmail: true},
		{OauthUserBase: model.OauthUserBase{Email: "someone@gmail.com"}, VerifiedEmail: true, Hd: "kozyops.com"},
	} {
		if kozyCheckDomain(bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
