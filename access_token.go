package OpenID

type AccessToken struct {
	Id     string
	Aud    string
	Sub    string
	Exp    int64
	Iss    string
	Scopes []string
}
