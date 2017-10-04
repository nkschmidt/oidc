package OpenID

type Code struct {
	Id           string
	Redirect_uri string
	Client_id    string
	Subject      string
	ExpireAt     int64
	Scopes       []string
}
