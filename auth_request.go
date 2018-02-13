package OpenID

import (
	"net/url"
	"strings"
	"fmt"
)

/*

	http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
	Definitions of Multiple-Valued Response Type Combinations

	This section defines combinations of the values code, token, and id_token, which are each individually registered Response Types.

	code token
	When supplied as the value for the response_type parameter, a successful response MUST include an Access Token, an Access Token Type, and an Authorization Code. The default Response Mode for this Response Type is the fragment encoding and the query encoding MUST NOT be used. Both successful and error responses SHOULD be returned using the supplied Response Mode, or if none is supplied, using the default Response Mode.
	code id_token
	When supplied as the value for the response_type parameter, a successful response MUST include both an Authorization Code and an id_token. The default Response Mode for this Response Type is the fragment encoding and the query encoding MUST NOT be used. Both successful and error responses SHOULD be returned using the supplied Response Mode, or if none is supplied, using the default Response Mode.
	id_token token
	When supplied as the value for the response_type parameter, a successful response MUST include an Access Token, an Access Token Type, and an id_token. The default Response Mode for this Response Type is the fragment encoding and the query encoding MUST NOT be used. Both successful and error responses SHOULD be returned using the supplied Response Mode, or if none is supplied, using the default Response Mode.
	code id_token token
	When supplied as the value for the response_type parameter, a successful response MUST include an Authorization Code, an id_token, an Access Token, and an Access Token Type. The default Response Mode for this Response Type is the fragment encoding and the query encoding MUST NOT be used. Both successful and error responses SHOULD be returned using the supplied Response Mode, or if none is supplied, using the default Response Mode.
	For all these Response Types, the request MAY include a state parameter, and if so, the Authorization Server MUST echo its value as a response parameter when issuing either a successful response or an error response.

*/

const (
	AUTH_RESPONSE_TYPE_CODE     = "code"
	AUTH_RESPONSE_TYPE_ID_TOKEN = "id_token"
	AUTH_RESPONSE_TYPE_MULTI_1  = "code token"
	AUTH_RESPONSE_TYPE_MULTI_2  = "code id_token"
	AUTH_RESPONSE_TYPE_MULTI_3  = "id_token token"
	AUTH_RESPONSE_TYPE_MULTI_4  = "code id_token token"

	RESPONSE_TYPE_FRAGMENT  = "fragment"
	RESPONSE_TYPE_QUERY     = "query"
	RESPONSE_TYPE_FORM_POST = "form_post"

	DISPLAY_PAGE  = "page"
	DISPLAY_POPUP = "popup"
	DISPLAY_TOUCH = "touch"
	DISPLAY_WAP   = "wap"

	PROMPT_NONE           = "none"
	PROMPT_LOGIN          = "login"
	PROMPT_CONSENT        = "consent"
	PROMPT_SELECT_ACCOUNT = "select_account"
)

type AuthRequest struct {
	Scopes                 []string
	Scope                  string
	ResponseType           string
	ClientId               string
	RedirectUri            string
	State                  string
	Response_mode          string
	Nonce                  string
	Display                string
	Prompt                 string
	Max_age                string
	Ui_locales             string
	Id_token_hint          string
	Login_hint             string
	Acr_values             string
	_flow                  string
	_code                  string
	_id_token              string
	_access_token          string
	_session_state         string
	_isPromptLogin         bool
	_isPromptNone          bool
	_isPromptConsent       bool
	_isPromptSelectAccount bool
	_expires_in                int64
}

func (a *AuthRequest) parse(values url.Values) {

	scopeSafe, _ := urlDecode(values.Get("scope"))
	scopes := strings.Split(scopeSafe, " ")
	for _, scope := range scopes {
		if len(scope) > 0 {
			a.Scopes = append(a.Scopes, scope)
		}
	}

	a.Scope = strings.Join(a.Scopes, " ")

	a.Prompt = values.Get("prompt")
	prompts := strings.Split(a.Prompt, " ")
	for _, prompt := range prompts {
		switch prompt {
		case PROMPT_LOGIN:
			a._isPromptLogin = true
			break
		case PROMPT_NONE:
			a._isPromptNone = true
			break
		case PROMPT_CONSENT:
			a._isPromptConsent = true
			break
		case PROMPT_SELECT_ACCOUNT:
			a._isPromptSelectAccount = true
			break
		}
	}

	a.ResponseType = strings.TrimSpace(values.Get("response_type"))

	a.ClientId = values.Get("client_id")

	a.RedirectUri = values.Get("redirect_uri")

	a.State = values.Get("state")

	a.Response_mode = values.Get("response_mode")

	a.Nonce = values.Get("nonce")

	a.Display = values.Get("display")

	a.Max_age = values.Get("max_age")

	a.Ui_locales = values.Get("ui_locales")

	a.Id_token_hint = values.Get("id_token_hint")

	// TODO может использоваться как подсказка для выбора активного аккаунта, отменяет выбор аккаунта
	a.Login_hint = values.Get("login_hint")

	a.Acr_values = values.Get("acr_values")
}

func (a *AuthRequest) validate(client *BaseClient) (err error) {

	if client == nil {
		err = Error{Err: "unauthorized_client", Desc: "unauthorized_client"}
		return
	}

	exist := false

	// Check scope
	if len(a.Scopes) == 0 {
		err = Error{Err: "invalid_scope", Desc: "invalid_scope"}
		return
	}

	for _, it := range a.Scopes {
		if it == "openid" {
			exist = true
			break
		}
	}

	if !exist {
		err = Error{Err: "invalid_scope", Desc: "invalid_scope"}
		return
	}

	// Check Prompt
	if a._isPromptNone {
		/*if len(a.Id_token_hint) == 0 {
			err = Error{Err: "invalid_request", Desc: "invalid_id_token_hint"}
			return
		}*/
	}

	// Check response_type
	switch a.ResponseType {
	case AUTH_RESPONSE_TYPE_CODE:
		a._flow = AUTHORIZATION_CODE_FLOW

	case AUTH_RESPONSE_TYPE_ID_TOKEN:
		a._flow = IMPLICIT_FLOW

	case AUTH_RESPONSE_TYPE_MULTI_3:
		a._flow = IMPLICIT_FLOW

	case AUTH_RESPONSE_TYPE_MULTI_2:
		a._flow = HYBRID_FLOW

	case AUTH_RESPONSE_TYPE_MULTI_1:
		a._flow = HYBRID_FLOW

	case AUTH_RESPONSE_TYPE_MULTI_4:
		a._flow = HYBRID_FLOW

	default:
		err = Error{Err: "unsupported_response_type", Desc: "unsupported_response_type"}
		return
	}

	// Chek response_mode
	if len(a.Response_mode) == 0 {
		if a._flow == AUTHORIZATION_CODE_FLOW {
			a.Response_mode = RESPONSE_TYPE_QUERY
		} else {
			a.Response_mode = RESPONSE_TYPE_FRAGMENT
		}
	} else {
		switch a.Response_mode {
		case RESPONSE_TYPE_FRAGMENT, RESPONSE_TYPE_QUERY, RESPONSE_TYPE_FORM_POST:
		default:
			err = Error{Err: "invalid_request", Desc: "unsupported_response_mode"}
			return
		}
	}

	if a._flow != AUTHORIZATION_CODE_FLOW && a.Response_mode == RESPONSE_TYPE_QUERY {
		err = Error{Err: "invalid_request", Desc: "invalid_response_mode"}
		return
	}

	// Check redirect_uri
	exist = false
	for _, uri := range client.Redirect_uris {
		if uri == a.RedirectUri {
			exist = true
		}
	}

	if !exist {
		err = Error{Err: "invalid_request", Desc: "invalid_redirect_uri"}
		return
	}

	// Check display
	switch a.Display {
	case DISPLAY_PAGE, DISPLAY_POPUP, DISPLAY_TOUCH, DISPLAY_WAP:
		break
	case "":
		a.Display = DISPLAY_PAGE
		break
	default:
		err = Error{Err: "invalid_request", Desc: "invalid_display"}
		return
	}

	return
}

func (a *AuthRequest) getPath() string {

	delimetr := ""
	if a.Response_mode == RESPONSE_TYPE_QUERY {
		delimetr = "?"
	} else {
		delimetr = "#"
	}

	state := "&session_state=" + a._session_state
	if len(a.State) > 0 {
		state += "&state=" + a.State
	}

	ext_token := "&token_type=Bearer&expires_in=" + fmt.Sprint(a._expires_in) + "&scope=" + strings.Join(a.Scopes, " ")

	switch a.ResponseType {
	case AUTH_RESPONSE_TYPE_CODE:
		return a.RedirectUri + delimetr + "code=" + a._code + state
	case AUTH_RESPONSE_TYPE_ID_TOKEN:
		return a.RedirectUri + delimetr + "id_token=" + a._id_token + state
	case AUTH_RESPONSE_TYPE_MULTI_1:
		return a.RedirectUri + delimetr + "code=" + a._code + "&token=" + a._access_token + state + ext_token
	case AUTH_RESPONSE_TYPE_MULTI_2:
		return a.RedirectUri + delimetr + "code=" + a._code + "&token_type=Bearer&id_token=" + a._id_token + state
	case AUTH_RESPONSE_TYPE_MULTI_3:
		return a.RedirectUri + delimetr + "token_type=Bearer&id_token=" + a._id_token + "&token=" + a._access_token + state + ext_token
	case AUTH_RESPONSE_TYPE_MULTI_4:
		return a.RedirectUri + delimetr + "code=" + a._code + "&token_type=Bearer&id_token=" + a._id_token + "&token=" + a._access_token + state + ext_token
	}

	return ""
}

func (a *AuthRequest) getForm() []byte {

	form := ""

	switch a.ResponseType {
	case AUTH_RESPONSE_TYPE_CODE:
		form = `
			<input type="hidden" name="code" value="` + a._code + `"/>
		`
		break
	case AUTH_RESPONSE_TYPE_ID_TOKEN:
		form = `
			<input type="hidden" name="id_token" value="` + a._id_token + `"/>
		`
		break

	case AUTH_RESPONSE_TYPE_MULTI_1:
		form = `
			<input type="hidden" name="code" value="` + a._code + `"/>
			<input type="hidden" name="token" value="` + a._access_token + `"/>
			<input type="hidden" name="token_type" value="Bearer"/>
			<input type="hidden" name="expires_in" value="` + fmt.Sprint(a._expires_in) + `"/>
			<input type="hidden" name="scope" value="` + strings.Join(a.Scopes, " ") + `"/>
		`
		break

	case AUTH_RESPONSE_TYPE_MULTI_2:
		form = `
			<input type="hidden" name="code" value="` + a._code + `"/>
			<input type="hidden" name="id_token" value="` + a._id_token + `"/>

		`
		break

	case AUTH_RESPONSE_TYPE_MULTI_3:
		form = `
			<input type="hidden" name="id_token" value="` + a._id_token + `"/>
			<input type="hidden" name="token" value="` + a._access_token + `"/>
			<input type="hidden" name="token_type" value="Bearer"/>
			<input type="hidden" name="expires_in" value="` + fmt.Sprint(a._expires_in) + `"/>
			<input type="hidden" name="scope" value="` + strings.Join(a.Scopes, " ") + `"/>
		`
		break

	case AUTH_RESPONSE_TYPE_MULTI_4:
		form = `
			<input type="hidden" name="code" value="` + a._code + `"/>
			<input type="hidden" name="id_token" value="` + a._id_token + `"/>
			<input type="hidden" name="token" value="` + a._access_token + `"/>
			<input type="hidden" name="token_type" value="Bearer"/>
			<input type="hidden" name="expires_in" value="` + fmt.Sprint(a._expires_in) + `"/>
			<input type="hidden" name="scope" value="` + strings.Join(a.Scopes, " ") + `"/>
		`
		break

	}

	return []byte(`
	<html>
		<head><title>Submit This Form</title></head>
		<body onload="javascript:document.forms[0].submit()">
			<form method="post" action="` + a.RedirectUri + `">
				<input type="hidden" name="state" value="` + a.State + `"/>
				<input type="hidden" name="session_state" value="` + a._session_state + `"/>
				` + form + `
			</form>
		</body>
	</html>
	`)
}
