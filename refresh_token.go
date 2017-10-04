package OpenID

type RefreshToken struct {
	Id          string
	AccessToken string
	Expire      int64
	ClientId    string
	Subject     string
	Scopes      []string
}
