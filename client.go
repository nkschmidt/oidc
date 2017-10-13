package OpenID

import "fmt"
import (
	"net/mail"
	"net/url"
)

type TimeoutSet struct {
	Token_timeout    uint64 `json:"token_timeout"`
	Id_token_timeout uint64 `json:"id_token_timeout"`
	Refresh_timeout  uint64 `json:"refresh_timeout"`
	Session_timeout  uint64 `json:"session_timeout"`
}

type ClientScope struct {
	Name   string   `json:"name"`
	Desc   string   `json:"desc"`
	Fields []string `json:"fields"`
}

type BaseClient struct {
	Application_type          string         `json:"application_type"`
	Response_types            []string       `json:"response_types"`
	Scopes                    []*ClientScope `json:"scopes"`
	Secret                    string         `json:"client_secret"`
	Redirect_uris             []string       `json:"redirect_uris"`
	Post_logout_redirect_uris []string       `json:"post_logout_redirect_uris"`
	Client_secret_expires_at  uint64         `json:"client_secret_expires_at"`


	Client_name string   `json:"client_name"`
	Contacts    []string `json:"contacts"`

	Logo_uri   string `json:"logo_uri"`
	Client_uri string `json:"client_uri"`
	Tos_uri    string `json:"tos_uri"`
	Policy_uri string `json:"policy_uri"`

	// TODO Разобраться с валидацией
	//Grant_types []string `json:"grant_types"`
}

func (s *ClientScope) validate() error {

	if len(s.Name) == 0 {
		return fmt.Errorf("%s", "Invalid scope name")
	}

	if len(s.Fields) == 0 {
		return fmt.Errorf("%s", "Invalid scope fields")
	}

	if len(s.Desc) == 0 {
		return fmt.Errorf("%s", "Invalid scope description")
	}

	return nil
}

func (b *BaseClient) GetBaseClient() *BaseClient {
	return b
}

func (b *BaseClient) genSecret() {
	b.Secret = genCode(64)
	b.Client_secret_expires_at = 0
}

func (b *BaseClient) validate() error {

	if len(b.Application_type) == 0 {
		b.Application_type = "web"
	}

	if len(b.Redirect_uris) == 0 {
		return fmt.Errorf("%s", "Invalid redirect uris")
	}

	switch b.Application_type {
	case "web", "native":
		break
	default:
		return fmt.Errorf("%s", "Invalid application type")
	}

	/* Валидация Redirect_uris и Post_logout_redirect_uris */
	{
		if len(b.Redirect_uris) == 0 {
			return fmt.Errorf("%s", "Invalid redirect url")
		}

		if len(b.Post_logout_redirect_uris) == 0 {
			return fmt.Errorf("%s", "Invalid post logout redirect url")
		}

		for _, uri := range b.Redirect_uris {
			u, err := url.ParseRequestURI(uri)
			if err != nil {
				return err
			}

			// для web только https и не localhost
			if b.Application_type == "web" {
				if u.Scheme != "https" || u.Host == "localhost" {
					return fmt.Errorf("%s: %s", "Invalid redirect url", uri)
				}
			}

			// для native - все что угодно
		}

		for _, uri := range b.Post_logout_redirect_uris {
			u, err := url.ParseRequestURI(uri)
			if err != nil {
				return err
			}

			// для web только https и не localhost
			if b.Application_type == "web" {
				if u.Scheme != "https" || u.Host == "localhost" {
					return fmt.Errorf("%s: %s", "Invalid post logout redirect url", uri)
				}
			}

			// для native - все что угодно
		}
	}

	/* Валидация Response_type */
	{
		if len(b.Response_types) == 0 {
			b.Response_types = append(b.Response_types, "code")
		}

		for _, item := range b.Response_types {
			switch item {
			case AUTH_RESPONSE_TYPE_CODE, AUTH_RESPONSE_TYPE_ID_TOKEN, AUTH_RESPONSE_TYPE_MULTI_1,
				AUTH_RESPONSE_TYPE_MULTI_2, AUTH_RESPONSE_TYPE_MULTI_3, AUTH_RESPONSE_TYPE_MULTI_4:
				break
			default:
				return fmt.Errorf("%s: %s", "Invalid response type", item)
			}
		}
	}

	/* Валидация Client_name, Logo_uri */
	{
		if len(b.Client_name) > 100 {
			b.Client_name = b.Client_name[:100]
		}

		if len(b.Logo_uri) > 5000 {
			b.Logo_uri = b.Logo_uri[:5000]
		}

		if len(b.Client_uri) > 5000 {
			b.Client_uri = b.Client_uri[:5000]
		}

		if len(b.Policy_uri) > 5000 {
			b.Policy_uri = b.Policy_uri[:5000]
		}

	}

	/* Валидация Contacts */
	{
		for _, contact := range b.Contacts {
			_, err := mail.ParseAddress(contact)
			if err != nil {
				return err
			}
		}
	}

	/* Валидация Scopes */
	{
		for _, scope := range b.Scopes {
			err := scope.validate()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type ClientInterface interface {
	GetBaseClient() *BaseClient
	GetId() string
}
