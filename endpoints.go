package OpenID

type Endpoints struct {
	Authorization_endpoint string `json:"authorization_endpoint"`
	Token_endpoint         string `json:"token_endpoint"`
	Userinfo_endpoint      string `json:"userinfo_endpoint"`
	End_session_endpoint   string `json:"end_session_endpoint"`
	Check_session_iframe   string `json:"check_session_iframe,omitempty"`
	Registration_endpoint  string `json:"registration_endpoint,omitempty"`
}
