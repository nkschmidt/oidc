package main

import (
	"encoding/json"
	"fmt"
	"github.com/NikSmith/oidc"
)


type Storage struct{}

var codes map[string]*OpenID.Code = map[string]*OpenID.Code{}
var _refresh map[string]*OpenID.RefreshToken = map[string]*OpenID.RefreshToken{}
var _access map[string]*OpenID.AccessToken = map[string]*OpenID.AccessToken{}

func (p Storage) GetGlobalAccessToken(tenant string) (token string, err error) {
	token = "secret_token"
	return
}

func (p Storage) GetUserBySub(provider, user_id string) (user *OpenID.BaseClaim, err error) {

	str := `{"extension": {"roles": ["admin"]}, "sub":"123"}`
	var u OpenID.BaseClaim
	err = json.Unmarshal([]byte(str), &u)
	user = &u
	return
}

func (p Storage) ClearCode(provider, code string) (err error) {

	delete(codes, code)
	return
}

func (p Storage) SetAccessToken(provider string, token *OpenID.AccessToken) (err error) {
	_access[token.Id] = token
	fmt.Println("SetAccessToken", _refresh)
	return
}

func (p Storage) GetAccessToken(provider, id string) (token *OpenID.AccessToken, err error) {
	token = _access[id]
	fmt.Println("GetAccessToken", token)
	return
}

func (p Storage) DelAccessToken(provider, id string) (err error) {
	delete(_access, id)
	fmt.Println("DelAccessToken", _refresh)
	return
}

func (p Storage) SetRefreshToken(provider string, refresh *OpenID.RefreshToken) (err error) {
	_refresh[refresh.Id] = refresh
	fmt.Println("SetRefreshToken", _refresh)
	return
}

func (p Storage) GetRefreshToken(provider, id string) (token *OpenID.RefreshToken, err error) {
	token = _refresh[id]
	fmt.Println("GetRefreshToken", token)
	return
}

func (p Storage) DelRefreshToken(provider, id string) (err error) {
	delete(_refresh, id)
	fmt.Println("DelRefreshToken", _refresh)
	return
}

func (p Storage) GetCode(provider, id string) (code *OpenID.Code, err error) {
	fmt.Println("GetCode", id, codes[id])
	code = codes[id]

	return
}

func (p Storage) SetCode(provider string, code *OpenID.Code) (err error) {
	fmt.Println("SetCode", provider, code)
	codes[code.Id] = code
	return
}

func (p Storage) AuthUser(provider, login, pwd string) (user *OpenID.BaseClaim, err error) {

	if login != "alice" || pwd != "secret" {
		return
	}
	str := `{"extension": {"roles": ["admin"]}, "sub":"123"}`
	var u OpenID.BaseClaim
	err = json.Unmarshal([]byte(str), &u)
	user = &u
	fmt.Println("AuthUser", provider, login, pwd, user)
	return

}

func (p Storage) GetClientById(provider, id string) (client OpenID.ClientInterface, err error) {


	custom := CustomClient{
		Id:"s6BhdRkqt3",
		BaseClient: &OpenID.BaseClient{
			Redirect_uris: []string{"http://localhost:8080"},
			Post_logout_redirect_uris: []string{"http://localhost:8080"},
			Application_type: "native",
			Response_types: []string{},
			Scopes: []*OpenID.ClientScope{
				&OpenID.ClientScope{
					Name: "roles",
					Desc: "Роли пользователя",
					Fields: []string{"roles"},
				},
				&OpenID.ClientScope{
					Name: "profile",
					Desc: "Профиль пользователя",
					Fields: []string{"address"},
				},
			},
			Secret: "password123",
			Token_timeout: 1000,
			Id_token_timeout: 1000,
			Refresh_timeout: 1000,
			Session_timeout: 1000,

		},
	}

	if id == "s6BhdRkqt3" {
		client = custom
	}

	fmt.Println("GetClientById", provider, id, client)

	return
}

func (p Storage) CreateClient(provider string, client *OpenID.BaseClient) (res OpenID.ClientInterface, err error) {

	fmt.Println("Create client", client)
	res = CustomClient{"11111", client}

	return
}

func (p Storage) UpdateClient(provider, id string, client *OpenID.BaseClient) (err error) {

	fmt.Println("Update client", id, client)

	return
}

func (p Storage) RemoveClient(provider, id string) (err error) {

	fmt.Println("REMOVE CLIENT", id)
	return
}

func (p Storage) GetClients(provider string) (clients []OpenID.ClientInterface, err error) {

	fmt.Println("Get clients", provider)
	custom := CustomClient{
		Id:"s6BhdRkqt3",
		BaseClient: &OpenID.BaseClient{
			Redirect_uris: []string{"http://localhost:8080"},
			Post_logout_redirect_uris: []string{"http://localhost:8080"},
			Application_type: "native",
			Response_types: []string{},
			Scopes: []*OpenID.ClientScope{
				&OpenID.ClientScope{
					Name: "roles",
					Desc: "Роли пользователя",
					Fields: []string{"roles"},
				},
				&OpenID.ClientScope{
					Name: "profile",
					Desc: "Профиль пользователя",
					Fields: []string{"address"},
				},
			},
			Secret: "password123",
			Token_timeout: 1000,
			Id_token_timeout: 1000,
			Refresh_timeout: 1000,
			Session_timeout: 1000,

		},
	}

	clients = make([]OpenID.ClientInterface, 0)
	clients = append(clients, custom)

	return
}