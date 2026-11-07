package service

// KozyOps changes. Each is switched on by an environment variable, so with
// none of them set this server behaves exactly like upstream.
//
//   KOZY_OAUTH_REDIRECT_URL     redirect URI for every OAuth provider, e.g.
//                               https://oauth.kozyops.com/callback. Our shared
//                               OAuth apps register only the central dispatcher,
//                               which forwards the callback to the origin in
//                               the state's "cb" claim, so the state is wrapped
//                               in that JWT shape too.
//   KOZY_ALLOWED_EMAIL_DOMAIN   Google/OIDC sign-in only for verified accounts
//                               of this Workspace domain (email and hd claim).
//   KOZY_OIDC_OP, KOZY_OIDC_CLIENT_ID, KOZY_OIDC_CLIENT_SECRET
//                               create or update a Google provider with
//                               auto-register on, at startup.
//   KOZY_ADMIN_EMAILS           comma-separated; these accounts become admins
//                               when they sign in through OAuth.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/lejianwen/rustdesk-api/v2/model"
)

func kozyRedirectURL(upstream string) string {
	if u := os.Getenv("KOZY_OAUTH_REDIRECT_URL"); u != "" {
		return u
	}
	return upstream
}

// kozyState returns an unsigned JWT-shaped state whose payload names this
// server as the dispatcher's callback origin. The state is also the key the
// client polls with, so it carries 32 random bytes.
func kozyState(upstream string) string {
	if os.Getenv("KOZY_OAUTH_REDIRECT_URL") == "" {
		return upstream
	}
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return upstream
	}
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]string{
		"cb": strings.TrimRight(Config.Rustdesk.ApiServer, "/"),
		"n":  enc.EncodeToString(n),
	})
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + "."
}

func kozyCheckDomain(u *model.OidcUser) error {
	domain := strings.ToLower(os.Getenv("KOZY_ALLOWED_EMAIL_DOMAIN"))
	if domain == "" {
		return nil
	}
	if !u.VerifiedEmail || u.Hd != domain || !strings.HasSuffix(strings.ToLower(u.Email), "@"+domain) {
		return errors.New("EmailDomainNotAllowed")
	}
	return nil
}

// KozyBootstrap creates or updates the OAuth provider named by KOZY_OIDC_OP.
func KozyBootstrap() {
	op := os.Getenv("KOZY_OIDC_OP")
	id := os.Getenv("KOZY_OIDC_CLIENT_ID")
	secret := os.Getenv("KOZY_OIDC_CLIENT_SECRET")
	if op == "" || id == "" || secret == "" {
		return
	}
	yes, s256 := true, model.PKCEMethodS256
	o := &model.Oauth{}
	DB.Where("op = ?", op).First(o)
	o.Op = op
	o.OauthType = model.OauthTypeOidc
	o.Issuer = model.IssuerGoogle
	o.ClientId = id
	o.ClientSecret = secret
	o.Scopes = "openid,email,profile"
	o.AutoRegister = &yes
	o.PkceEnable = &yes
	o.PkceMethod = s256
	if err := DB.Save(o).Error; err != nil {
		Logger.Error("kozy: saving OAuth provider ", op, ": ", err)
		return
	}
	Logger.Info("kozy: OAuth provider ", op, " configured")
}

// KozyPromoteAdmin makes a user an admin when their email is in KOZY_ADMIN_EMAILS.
func KozyPromoteAdmin(user *model.User) {
	if user == nil || user.Id == 0 || (user.IsAdmin != nil && *user.IsAdmin) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(user.Email))
	for _, a := range strings.Split(os.Getenv("KOZY_ADMIN_EMAILS"), ",") {
		if email != "" && strings.ToLower(strings.TrimSpace(a)) == email {
			yes := true
			user.IsAdmin = &yes
			DB.Model(user).Update("is_admin", true)
			Logger.Info("kozy: ", email, " is now an admin")
			return
		}
	}
}
