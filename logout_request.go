package OpenID

import (
	"fmt"
	"net/url"
)

type LogoutRequest struct {
	id_token_hint            string
	post_logout_redirect_uri string
	state                    string
	isExistIdToken           bool
}

func (l *LogoutRequest) parse(values url.Values) {
	l.id_token_hint = values.Get("id_token_hint")
	if len(l.id_token_hint) > 0 {
		l.isExistIdToken = true
	}
	l.post_logout_redirect_uri = values.Get("post_logout_redirect_uri")
	l.state = values.Get("state")
}

func (l *LogoutRequest) validate(client *BaseClient) (err error) {

	if len(l.post_logout_redirect_uri) > 0 {
		for _, uri := range client.Post_logout_redirect_uris {
			if uri == l.post_logout_redirect_uri {
				return nil
			}
		}

		return fmt.Errorf("%s", "invalid_redirect_uri")
	}

	return nil
}
