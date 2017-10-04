package OpenID

import (
	"fmt"
	"net/url"
)

const (
	GRANT_TYPE_REFRESH_TOKEN = "refresh_token"
	GRANT_TYPE_AUTH_CODE     = "authorization_code"

	CLIENT_SECRET_METHOD_BASIC = "client_secret_basic"
	CLIENT_SECRET_METHOD_POST  = ""
	CLIENT_SECRET_METHOD_JWT   = ""
)

type TokenRequest struct {
	grant_type    string
	code          string
	redirect_uri  string
	refresh_token string

	// Информация о клиенте(приложении)
	client_id     string
	client_secret string

	client_assertion_type string
	client_assertion      string
}

func (t *TokenRequest) parseForm(values url.Values) {

	t.grant_type = values.Get("grant_type")
	t.refresh_token = values.Get("refresh_token")
	t.code = values.Get("code")
	t.redirect_uri = values.Get("redirect_uri")
	t.client_id = values.Get("client_id")
	t.client_secret = values.Get("client_secret")

}

func (t *TokenRequest) validate() (err error) {

	//check grant_type
	switch t.grant_type {
	case GRANT_TYPE_AUTH_CODE:
		if len(t.code) == 0 {
			return fmt.Errorf("%s", "invalid code")
		}
		break
	case GRANT_TYPE_REFRESH_TOKEN:
		if len(t.refresh_token) == 0 {
			return fmt.Errorf("%s", "invalid refresh_token")
		}
		break
	default:
		return fmt.Errorf("%s", "invalid grant_type")
	}

	return
}
