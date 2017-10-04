package OpenID

import (
	"encoding/json"
	"strings"
)

type Settings struct {
	Issuer string `json:"issuer"`

	enabled_access_control bool

	*Endpoints

	Token_endpoint_auth_methods_supported            []string `json:"token_endpoint_auth_methods_supported"`
	Token_endpoint_auth_signing_alg_values_supported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	Scopes_supported                                 []string `json:"scopes_supported"`
	Response_types_supported                         []string `json:"response_types_supported"`
	Display_values_supported                         []string `json:"display_values_supported"`
	Subject_types_supported                          []string `json:"subject_types_supported"`
	Claim_types_supported                            []string `json:"claim_types_supported"`
	Claims_supported                                 []string `json:"claims_supported"`
	Claims_parameter_supported                       bool     `json:"claims_parameter_supported"`
	Ui_locales_supported                             []string `json:"ui_locales_supported"`
	Userinfo_signing_alg_values_supported            []string `json:"userinfo_signing_alg_values_supported"`
	Userinfo_encryption_alg_values_supported         []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	Userinfo_encryption_enc_values_supported         []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	Id_token_signing_alg_values_supported            []string `json:"id_token_signing_alg_values_supported"`
	Id_token_encryption_alg_values_supported         []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	Id_token_encryption_enc_values_supported         []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	Request_object_signing_alg_values_supported      []string `json:"request_object_signing_alg_values_supported,omitempty"`
	Service_documentation                            string   `json:"service_documentation,omitempty"`
	Acr_values_supported                             []string `json:"acr_values_supported,omitempty"`
	Response_modes_supported                         []string `json:"response_modes_supported"`
	Jwks_uri                                         string   `json:"jwks_uri"`
}

func (s Settings) toJSON(tenant string) (res []byte) {

	type customSettings struct {
		Settings
		Endpoints
	}

	settings := customSettings{
		s,
		Endpoints{
			Authorization_endpoint: strings.Replace(s.Authorization_endpoint, "{tenant}", tenant, -1),
			Token_endpoint:         strings.Replace(s.Token_endpoint, "{tenant}", tenant, -1),
			Userinfo_endpoint:      strings.Replace(s.Userinfo_endpoint, "{tenant}", tenant, -1),
			Check_session_iframe:   strings.Replace(s.Check_session_iframe, "{tenant}", tenant, -1),
			End_session_endpoint:   strings.Replace(s.End_session_endpoint, "{tenant}", tenant, -1),
			Registration_endpoint:  strings.Replace(s.Registration_endpoint, "{tenant}", tenant, -1),
		},
	}

	settings.Issuer = strings.Replace(s.Issuer, "{tenant}", tenant, -1)

	res, _ = json.Marshal(settings)

	return
}
