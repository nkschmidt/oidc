package main

import "github.com/NikSmith/oidc"

type CustomClient struct {
	Id string `json:"client_id"`
	*OpenID.BaseClient
}

func (c CustomClient) GetId() string {
	return c.Id
}
