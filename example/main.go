package main

import (
	"github.com/NikSmith/oidc"
	"github.com/gorilla/mux"
	"html/template"
	"log"
	"net/http"
	"os"
)

func main() {

	l := log.New(os.Stdout, "", 1)

	openid := OpenID.New()
	store := Storage{}
	openid.AddStorage(store)
	openid.SetLogger(l)

	tpl, err := template.New("template.html").ParseFiles("template.html")
	if err != nil {
		panic(err)
	}

	endpoints := OpenID.Endpoints{
		Authorization_endpoint: "http://localhost/oidc/{tenant}/authorize",
		Token_endpoint:         "http://localhost/oidc/{tenant}/token",
		Userinfo_endpoint:      "http://localhost/oidc/{tenant}/userinfo",
		End_session_endpoint:   "http://localhost/oidc/{tenant}/logout",
		Check_session_iframe:   "http://localhost/oidc/{tenant}/session",
		Registration_endpoint:  "http://localhost/oidc/{tenant}/registration",
	}

	openid.SetIssue("http://localhost/oidc/{tenant}")
	openid.SetEndpoints(&endpoints)
	openid.EnableAccesControl()

	openid.AddTemplate(tpl)

	r := mux.NewRouter()

	r.HandleFunc("/oidc/{tenant}/userinfo", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		openid.Userinfo(vars["tenant"], w, r)
	}).Methods("GET", "POST")

	r.HandleFunc("/oidc/{tenant}/authorize", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		openid.Authorize(vars["tenant"], w, r)
	}).Methods("GET", "POST")

	r.HandleFunc("/oidc/{tenant}/token", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		openid.Token(vars["tenant"], w, r)
	}).Methods("POST")

	r.HandleFunc("/oidc/{tenant}/session", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		openid.CheckSession(vars["tenant"], w, r)
	}).Methods("GET")

	r.HandleFunc("/oidc/{tenant}/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		openid.Discovery(vars["tenant"], w, r)
	}).Methods("GET")

	r.HandleFunc("/oidc/{tenant}/logout", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		openid.Logout(vars["tenant"], w, r)
	}).Methods("GET")

	r.HandleFunc("/oidc/{tenant}/certs", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		openid.Jwks(vars["tenant"], w, r)
	}).Methods("GET")

	r.HandleFunc("/oidc/{tenant}/registration", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		openid.Registration(vars["tenant"], w, r)
	}).Methods(http.MethodPost, http.MethodGet, http.MethodDelete)

	err = http.ListenAndServe(":80", r)
	if err != nil {
		panic(err)
	}

}
