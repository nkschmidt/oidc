package OpenID

type Storage interface {
	GetTimeoutSet(string) (*TimeoutSet, error)

	GetGlobalAccessToken(tenant string) (token string, err error)

	GetClientById(tenant, id string) (client ClientInterface, err error)

	CreateClient(tenant string, client *BaseClient) (res ClientInterface, err error)

	RemoveClient(tenant, id string) error

	GetClients(string) ([]ClientInterface, error)

	UpdateClient(string, string, *BaseClient) error

	GetUserBySub(tenant, user_id string) (user *BaseClaim, err error)

	AuthUser(tenant, login, password string) (user *BaseClaim, err error)

	SetCode(tenant string, code *Code) (err error)

	GetCode(tenant, id string) (code *Code, err error)

	ClearCode(tenant, code string) (err error)

	SetAccessToken(tenant string, accessToken *AccessToken) (err error)

	GetAccessToken(tenant string, id string) (accessToken *AccessToken, err error)

	DelAccessToken(tenant string, id string) (err error)

	SetRefreshToken(tenant string, refresh *RefreshToken) (err error)

	GetRefreshToken(tenant string, id string) (refresh *RefreshToken, err error)

	DelRefreshToken(tenant string, id string) (err error)
}
