package OpenID

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//todo Promt=none - session_state

var src = rand.NewSource(time.Now().UnixNano())

const letterBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

const (
	AUTHORIZATION_CODE_FLOW = "AUTHORIZATION_CODE_FLOW"
	IMPLICIT_FLOW           = "IMPLICIT_FLOW"
	HYBRID_FLOW             = "HYBRID_FLOW"
)

type OpenID struct {
	storage     Storage
	settings    *Settings
	tpl         *template.Template
	confirmTpl  *template.Template
	publicKeys  []*Keys
	privateKeys []*Keys
}

func New() *OpenID {
	return &OpenID{
		publicKeys:  []*Keys{},
		privateKeys: []*Keys{},
		settings: &Settings{
			Token_endpoint_auth_methods_supported:            []string{"client_secret_basic", "client_secret_post"},
			Token_endpoint_auth_signing_alg_values_supported: []string{},
			Scopes_supported:                                 []string{"openid", "profile", "email", "phone", "offline_access"},
			Response_types_supported:                         []string{"code", "code id_token", "code token", "id_token", "token id_token", "code id_token token"}, //todo доработать
			Display_values_supported:                         []string{"page", "popup"},                                                                            // not supported "touch" and "wap"
			Subject_types_supported:                          []string{"pairwise"},

			// http://openid.net/specs/openid-connect-core-1_0.html#ClaimTypes
			Claim_types_supported: []string{"normal"},
			Claims_supported: []string{"sub", "name", "given_name", "family_name", "middle_name", "nickname",
				"preferred_username", "profile", "picture", "website", "gender", "birthday", "updated_at", "phone_number",
				"phone_number_verified", "email", "email_verified", "locale", "zoneinfo"},
			Claims_parameter_supported:            true,
			Ui_locales_supported:                  []string{"en-US"},
			Userinfo_signing_alg_values_supported: []string{"none"},
			Id_token_signing_alg_values_supported: []string{"HS256"}, //todo support RS256
			Response_modes_supported:              []string{"query", "fragment", "form_post"},
		},
	}
}

func (oID *OpenID) send(w http.ResponseWriter, data []byte) {
	w.Write(data)
}

func (oID *OpenID) genIdToken(tenant string, clientInterface ClientInterface, nonce string, scopes []string, user *BaseClaim) (token string, err error) {

	/*

		iss
		REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a case sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.
		sub
		REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The sub value is a case sensitive string.
		aud
		REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
		exp
		REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing. The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
		iat
		REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
		auth_time
		Time when the End-User authentication occurred. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
		nonce
		String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case sensitive string.

	*/

	client := clientInterface.GetBaseClient()

	now := time.Now()
	duration := time.Duration(client.Id_token_timeout) * time.Second

	claim := jwt.MapClaims{}

	for _, el := range scopes {
		if el == "openid" || el == "offline_access" {
			continue
		}

		for _, scope := range client.Scopes {
			if scope.Name == el {
				claim[el] = user.Get(scope.Name, scope.Fields)
				continue
			}
		}
	}

	claim["aud"] = clientInterface.GetId()
	claim["nonce"] = nonce
	claim["sub"] = user.Sub
	claim["exp"] = now.Add(duration).Unix()
	claim["iss"] = oID.getIssuer(tenant)
	claim["iat"] = now.Unix()

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	token, err = jwtToken.SignedString([]byte(client.Secret))

	return
}

/*func (oID *OpenID) genAccessToken(clientInterface ClientInterface, user_id string, scopes []string) (token_string string, expire int64, err error) {

	client := clientInterface.GetBaseClient()

	duration := time.Duration(client.Token_timeout) * time.Second

	expire = time.Now().Add(duration).Unix()
	claims := jwt.MapClaims{
		"aud":    clientInterface.GetId(),
		"sub":    user_id,
		"exp":    expire,
		"iss":    oID.issue,
		"scopes": scopes,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token_string, err = token.SignedString([]byte(client.Secret))
	if err != nil {
		return
	}

	return
}*/

func (oID OpenID) readJWTToken(provider, tokenString string) (claims jwt.MapClaims, err error) {

	var ok bool
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return nil, nil
	})

	if token == nil {
		return nil, fmt.Errorf("%v", "Invalid token")
	}

	if claims, ok = token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	} else {
		return nil, err
	}

}

func (oID OpenID) parseJWTToken(provider, secret, tokenString string) (claims jwt.MapClaims, err error) {

	var ok bool

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if token == nil {
		return nil, fmt.Errorf("%v", "Invalid token")
	}

	if claims, ok = token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}

}

func (oID *OpenID) sendJson(data interface{}, w http.ResponseWriter, status int) {

	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
	}

	bt, _ := json.Marshal(data)
	w.Write(bt)
}

func (oID *OpenID) error(err error, uri, state string, w http.ResponseWriter, r *http.Request) {
	error := err.(Error)
	error.include("state", state)

	if len(uri) > 0 {
		http.Redirect(w, r, uri+error.query(), 302)
	} else {
		w.WriteHeader(400)
		w.Header().Set("content-type", "application/json")
		w.Write(error.toJSON())
	}

}

func (oID OpenID) setCORS(w http.ResponseWriter, r *http.Request) {

	allowedHeaders := "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization,X-CSRF-Token"
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		w.Header().Set("Access-Control-Expose-Headers", "Authorization")
	}
}

func (oID OpenID) getAccount(user_id, client_id string, accounts []*jwt.MapClaims) *jwt.MapClaims {

	var sub, aud string

	for _, account := range accounts {
		sub, _ = (*account)["sub"].(string)
		if sub != user_id {
			continue
		}

		if client_id != "" {
			aud, _ = (*account)["aud"].(string)
			if client_id != aud {
				continue
			}
		}

		return account
	}

	return nil
}

func (oID *OpenID) getAccountBySession(session string, accounts []*jwt.MapClaims) *jwt.MapClaims {

	var sess_id string

	for _, account := range accounts {
		sess_id, _ = (*account)["session"].(string)
		if sess_id == session {
			return account
		}
	}

	return nil
}

func (oID *OpenID) getAccounts(provider, client_id, client_secret string, r *http.Request) (current *jwt.MapClaims, accounts []*jwt.MapClaims) {

	// читаем id текущего
	c, _ := r.Cookie("session")

	// Читаем все куки, выбираем список аккаунтов и текущий
	cookies := r.Cookies()

	for _, cookie := range cookies {

		if len(cookie.Name) <= 8 {
			continue
		}

		if cookie.Name[:8] != "session_" {
			continue
		}

		claim, err := oID.parseJWTToken(provider, client_secret, cookie.Value)
		if err != nil {
			continue
		}

		if c != nil && c.Value == cookie.Name {
			current = &claim
		}

		if client_id != "" && client_id != claim["aud"] {
			continue
		}

		claim["session"] = cookie.Name

		accounts = append(accounts, &claim)
	}

	return
}

func (oID *OpenID) SetIssue(i string) {
	oID.settings.Issuer = i
}

func (oID *OpenID) setSession(tenant string, w http.ResponseWriter, claim *BaseClaim, path string, clientInterface ClientInterface) (session_state string) {

	client := clientInterface.GetBaseClient()
	if client == nil {
		return
	}
	now := time.Now()

	u, _ := url.Parse(path)

	expireAt := now.Add(time.Duration(client.Session_timeout) * time.Second)

	claims := jwt.MapClaims{
		"aud":     clientInterface.GetId(),
		"sub":     claim.Sub,
		"name":    claim.Name,
		"picture": claim.Picture,
		"iat":     now.Unix(),
		"exp":     expireAt,
		"iss":     oID.getIssuer(tenant),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token_string, err := token.SignedString([]byte(client.Secret))
	if err != nil {
		return
	}

	session_name := "session_" + genCode(10)

	cookie := &http.Cookie{
		session_name,
		token_string,
		u.Path,
		u.Host,
		expireAt,
		expireAt.Format(time.UnixDate),
		int(client.Session_timeout),
		false,
		false,
		session_name + token_string,
		[]string{session_name + token_string},
	}

	state := &http.Cookie{
		"session",
		session_name,
		u.Path,
		u.Host,
		expireAt,
		expireAt.Format(time.UnixDate),
		int(client.Session_timeout),
		false,
		false,
		"session=" + token_string,
		[]string{"session=" + session_name},
	}

	salt := genCode(6)

	h := sha256.New()
	h.Write([]byte(clientInterface.GetId() + " " + token_string + " " + salt))

	session_state = fmt.Sprintf("%x", h.Sum(nil)) + "." + salt

	http.SetCookie(w, cookie)
	http.SetCookie(w, state)

	return
}

func (oID *OpenID) AddTemplate(tpl *template.Template) {
	oID.tpl = tpl
}

func (oID *OpenID) AddStorage(s Storage) {
	oID.storage = s
}

func (oID *OpenID) getIssuer(tenant string) string {
	return strings.Replace(oID.settings.Issuer, "{tenant}", tenant, -1)
}

func (oID OpenID) SetEndpoints(endpoints *Endpoints) {
	oID.settings.Endpoints = endpoints
}

func (oID OpenID) CheckSession(tenant string, w http.ResponseWriter, r *http.Request) {

	oID.send(w, []byte(`
		<html><head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Check Session IFrame</title>
</head>
<body>
	<script>
		/**
		 * [js-sha256]{@link https://github.com/emn178/js-sha256}
		 *
		 * @version 0.6.0
		 * @author Chen, Yi-Cyuan [emn178@gmail.com]
		 * @copyright Chen, Yi-Cyuan 2014-2017
		 * @license MIT
		 */
		!function(){"use strict";function t(t,i){i?(p[0]=p[16]=p[1]=p[2]=p[3]=p[4]=p[5]=p[6]=p[7]=p[8]=p[9]=p[10]=p[11]=p[12]=p[13]=p[14]=p[15]=0,this.blocks=p):this.blocks=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],t?(this.h0=3238371032,this.h1=914150663,this.h2=812702999,this.h3=4144912697,this.h4=4290775857,this.h5=1750603025,this.h6=1694076839,this.h7=3204075428):(this.h0=1779033703,this.h1=3144134277,this.h2=1013904242,this.h3=2773480762,this.h4=1359893119,this.h5=2600822924,this.h6=528734635,this.h7=1541459225),this.block=this.start=this.bytes=0,this.finalized=this.hashed=!1,this.first=!0,this.is224=t}function i(i,r,e){var n="string"!=typeof i;if(n){if(null===i||void 0===i)throw h;i.constructor===s.ArrayBuffer&&(i=new Uint8Array(i))}var o=i.length;if(n){if("number"!=typeof o||!Array.isArray(i)&&(!a||!ArrayBuffer.isView(i)))throw h}else{for(var f,u=[],o=i.length,c=0,y=0;o>y;++y)f=i.charCodeAt(y),128>f?u[c++]=f:2048>f?(u[c++]=192|f>>6,u[c++]=128|63&f):55296>f||f>=57344?(u[c++]=224|f>>12,u[c++]=128|f>>6&63,u[c++]=128|63&f):(f=65536+((1023&f)<<10|1023&i.charCodeAt(++y)),u[c++]=240|f>>18,u[c++]=128|f>>12&63,u[c++]=128|f>>6&63,u[c++]=128|63&f);i=u}i.length>64&&(i=new t(r,!0).update(i).array());for(var p=[],l=[],y=0;64>y;++y){var d=i[y]||0;p[y]=92^d,l[y]=54^d}t.call(this,r,e),this.update(l),this.oKeyPad=p,this.inner=!0,this.sharedMemory=e}var h="input is invalid type",s="object"==typeof window?window:{},r=!s.JS_SHA256_NO_NODE_JS&&"object"==typeof process&&process.versions&&process.versions.node;r&&(s=global);var e=!s.JS_SHA256_NO_COMMON_JS&&"object"==typeof module&&module.exports,n="function"==typeof define&&define.amd,a="undefined"!=typeof ArrayBuffer,o="0123456789abcdef".split(""),f=[-2147483648,8388608,32768,128],u=[24,16,8,0],c=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],y=["hex","array","digest","arrayBuffer"],p=[];(s.JS_SHA256_NO_NODE_JS||!Array.isArray)&&(Array.isArray=function(t){return"[object Array]"===Object.prototype.toString.call(t)});var l=function(i,h){return function(s){return new t(h,!0).update(s)[i]()}},d=function(i){var h=l("hex",i);r&&(h=v(h,i)),h.create=function(){return new t(i)},h.update=function(t){return h.create().update(t)};for(var s=0;s<y.length;++s){var e=y[s];h[e]=l(e,i)}return h},v=function(t,i){var s=require("crypto"),r=require("buffer").Buffer,e=i?"sha224":"sha256",n=function(i){if("string"==typeof i)return s.createHash(e).update(i,"utf8").digest("hex");if(null===i||void 0===i)throw h;return i.constructor===ArrayBuffer&&(i=new Uint8Array(i)),Array.isArray(i)||ArrayBuffer.isView(i)||i.constructor===r?s.createHash(e).update(new r(i)).digest("hex"):t(i)};return n},A=function(t,h){return function(s,r){return new i(s,h,!0).update(r)[t]()}},w=function(t){var h=A("hex",t);h.create=function(h){return new i(h,t)},h.update=function(t,i){return h.create(t).update(i)};for(var s=0;s<y.length;++s){var r=y[s];h[r]=A(r,t)}return h};t.prototype.update=function(t){if(!this.finalized){var i="string"!=typeof t;if(i){if(null===t||void 0===t)throw h;t.constructor===s.ArrayBuffer&&(t=new Uint8Array(t))}var r=t.length;if(!(!i||"number"==typeof r&&(Array.isArray(t)||a&&ArrayBuffer.isView(t))))throw h;for(var e,n,o=0,f=this.blocks;r>o;){if(this.hashed&&(this.hashed=!1,f[0]=this.block,f[16]=f[1]=f[2]=f[3]=f[4]=f[5]=f[6]=f[7]=f[8]=f[9]=f[10]=f[11]=f[12]=f[13]=f[14]=f[15]=0),i)for(n=this.start;r>o&&64>n;++o)f[n>>2]|=t[o]<<u[3&n++];else for(n=this.start;r>o&&64>n;++o)e=t.charCodeAt(o),128>e?f[n>>2]|=e<<u[3&n++]:2048>e?(f[n>>2]|=(192|e>>6)<<u[3&n++],f[n>>2]|=(128|63&e)<<u[3&n++]):55296>e||e>=57344?(f[n>>2]|=(224|e>>12)<<u[3&n++],f[n>>2]|=(128|e>>6&63)<<u[3&n++],f[n>>2]|=(128|63&e)<<u[3&n++]):(e=65536+((1023&e)<<10|1023&t.charCodeAt(++o)),f[n>>2]|=(240|e>>18)<<u[3&n++],f[n>>2]|=(128|e>>12&63)<<u[3&n++],f[n>>2]|=(128|e>>6&63)<<u[3&n++],f[n>>2]|=(128|63&e)<<u[3&n++]);this.lastByteIndex=n,this.bytes+=n-this.start,n>=64?(this.block=f[16],this.start=n-64,this.hash(),this.hashed=!0):this.start=n}return this}},t.prototype.finalize=function(){if(!this.finalized){this.finalized=!0;var t=this.blocks,i=this.lastByteIndex;t[16]=this.block,t[i>>2]|=f[3&i],this.block=t[16],i>=56&&(this.hashed||this.hash(),t[0]=this.block,t[16]=t[1]=t[2]=t[3]=t[4]=t[5]=t[6]=t[7]=t[8]=t[9]=t[10]=t[11]=t[12]=t[13]=t[14]=t[15]=0),t[15]=this.bytes<<3,this.hash()}},t.prototype.hash=function(){var t,i,h,s,r,e,n,a,o,f,u,y=this.h0,p=this.h1,l=this.h2,d=this.h3,v=this.h4,A=this.h5,w=this.h6,b=this.h7,g=this.blocks;for(t=16;64>t;++t)r=g[t-15],i=(r>>>7|r<<25)^(r>>>18|r<<14)^r>>>3,r=g[t-2],h=(r>>>17|r<<15)^(r>>>19|r<<13)^r>>>10,g[t]=g[t-16]+i+g[t-7]+h<<0;for(u=p&l,t=0;64>t;t+=4)this.first?(this.is224?(a=300032,r=g[0]-1413257819,b=r-150054599<<0,d=r+24177077<<0):(a=704751109,r=g[0]-210244248,b=r-1521486534<<0,d=r+143694565<<0),this.first=!1):(i=(y>>>2|y<<30)^(y>>>13|y<<19)^(y>>>22|y<<10),h=(v>>>6|v<<26)^(v>>>11|v<<21)^(v>>>25|v<<7),a=y&p,s=a^y&l^u,n=v&A^~v&w,r=b+h+n+c[t]+g[t],e=i+s,b=d+r<<0,d=r+e<<0),i=(d>>>2|d<<30)^(d>>>13|d<<19)^(d>>>22|d<<10),h=(b>>>6|b<<26)^(b>>>11|b<<21)^(b>>>25|b<<7),o=d&y,s=o^d&p^a,n=b&v^~b&A,r=w+h+n+c[t+1]+g[t+1],e=i+s,w=l+r<<0,l=r+e<<0,i=(l>>>2|l<<30)^(l>>>13|l<<19)^(l>>>22|l<<10),h=(w>>>6|w<<26)^(w>>>11|w<<21)^(w>>>25|w<<7),f=l&d,s=f^l&y^o,n=w&b^~w&v,r=A+h+n+c[t+2]+g[t+2],e=i+s,A=p+r<<0,p=r+e<<0,i=(p>>>2|p<<30)^(p>>>13|p<<19)^(p>>>22|p<<10),h=(A>>>6|A<<26)^(A>>>11|A<<21)^(A>>>25|A<<7),u=p&l,s=u^p&d^f,n=A&w^~A&b,r=v+h+n+c[t+3]+g[t+3],e=i+s,v=y+r<<0,y=r+e<<0;this.h0=this.h0+y<<0,this.h1=this.h1+p<<0,this.h2=this.h2+l<<0,this.h3=this.h3+d<<0,this.h4=this.h4+v<<0,this.h5=this.h5+A<<0,this.h6=this.h6+w<<0,this.h7=this.h7+b<<0},t.prototype.hex=function(){this.finalize();var t=this.h0,i=this.h1,h=this.h2,s=this.h3,r=this.h4,e=this.h5,n=this.h6,a=this.h7,f=o[t>>28&15]+o[t>>24&15]+o[t>>20&15]+o[t>>16&15]+o[t>>12&15]+o[t>>8&15]+o[t>>4&15]+o[15&t]+o[i>>28&15]+o[i>>24&15]+o[i>>20&15]+o[i>>16&15]+o[i>>12&15]+o[i>>8&15]+o[i>>4&15]+o[15&i]+o[h>>28&15]+o[h>>24&15]+o[h>>20&15]+o[h>>16&15]+o[h>>12&15]+o[h>>8&15]+o[h>>4&15]+o[15&h]+o[s>>28&15]+o[s>>24&15]+o[s>>20&15]+o[s>>16&15]+o[s>>12&15]+o[s>>8&15]+o[s>>4&15]+o[15&s]+o[r>>28&15]+o[r>>24&15]+o[r>>20&15]+o[r>>16&15]+o[r>>12&15]+o[r>>8&15]+o[r>>4&15]+o[15&r]+o[e>>28&15]+o[e>>24&15]+o[e>>20&15]+o[e>>16&15]+o[e>>12&15]+o[e>>8&15]+o[e>>4&15]+o[15&e]+o[n>>28&15]+o[n>>24&15]+o[n>>20&15]+o[n>>16&15]+o[n>>12&15]+o[n>>8&15]+o[n>>4&15]+o[15&n];return this.is224||(f+=o[a>>28&15]+o[a>>24&15]+o[a>>20&15]+o[a>>16&15]+o[a>>12&15]+o[a>>8&15]+o[a>>4&15]+o[15&a]),f},t.prototype.toString=t.prototype.hex,t.prototype.digest=function(){this.finalize();var t=this.h0,i=this.h1,h=this.h2,s=this.h3,r=this.h4,e=this.h5,n=this.h6,a=this.h7,o=[t>>24&255,t>>16&255,t>>8&255,255&t,i>>24&255,i>>16&255,i>>8&255,255&i,h>>24&255,h>>16&255,h>>8&255,255&h,s>>24&255,s>>16&255,s>>8&255,255&s,r>>24&255,r>>16&255,r>>8&255,255&r,e>>24&255,e>>16&255,e>>8&255,255&e,n>>24&255,n>>16&255,n>>8&255,255&n];return this.is224||o.push(a>>24&255,a>>16&255,a>>8&255,255&a),o},t.prototype.array=t.prototype.digest,t.prototype.arrayBuffer=function(){this.finalize();var t=new ArrayBuffer(this.is224?28:32),i=new DataView(t);return i.setUint32(0,this.h0),i.setUint32(4,this.h1),i.setUint32(8,this.h2),i.setUint32(12,this.h3),i.setUint32(16,this.h4),i.setUint32(20,this.h5),i.setUint32(24,this.h6),this.is224||i.setUint32(28,this.h7),t},i.prototype=new t,i.prototype.finalize=function(){if(t.prototype.finalize.call(this),this.inner){this.inner=!1;var i=this.array();t.call(this,this.is224,this.sharedMemory),this.update(this.oKeyPad),this.update(i),t.prototype.finalize.call(this)}};var b=d();b.sha256=b,b.sha224=d(!0),b.sha256.hmac=w(),b.sha224.hmac=w(!0),e?module.exports=b:(s.sha256=b.sha256,s.sha224=b.sha224,n&&define(function(){return b}))}();
	</script>
    <script>



	function get_op_browser_state() {

		return '';
	}

	function getCookies() {
		var allCookies = document.cookie;
		var cookies = allCookies.split(';');
		return cookies.map(function (value) {
			var parts = value.trim().split('=');
			if (parts.length === 2) {
				return {
					name: parts[0].trim(),
					value: parts[1].trim()
				};
			}
		}).filter(function (item) {
			return item && item.name && item.value;
		});
	}

	function getCookieByName(name) {
		var cookies = getCookies().filter(function (cookie) {
			return (cookie.name == name);
		});
		return cookies[0] && cookies[0].value;
	}

	function receiveMessage(e){
		try {

			if (!e.origin || e.data.split(' ').length != 2) {
				e.source.postMessage('error', e.origin);
				return;
			}

			var client_id = e.data.split(' ')[0];
			var session_state = e.data.split(' ')[1];
			var salt = session_state.split('.')[1];

			if (!salt || !client_id || !session_state) {
				e.source.postMessage('error', e.origin);
				return;
			}


			var cookie = getCookieByName('session');
			if (!cookie) {
				e.source.postMessage('changed', e.origin);
				return;
			}

			var session = getCookieByName(cookie);
			if (!session) {
				e.source.postMessage('changed', e.origin);
				return;
			}


			var ss = sha256(client_id + ' ' + session.trim() + ' ' + salt) + "." + salt;
			var result = session_state == ss ? 'unchanged' : 'changed';

			e.source.postMessage(result, e.origin);
		} catch(err) {
			e.source.postMessage('error', e.origin);
		}
	};

	if (window.parent !== window) {
		window.addEventListener("message", receiveMessage, false);
	}


    </script>
</body></html>

	`))
}

func (oID *OpenID) Authorize(provider string, w http.ResponseWriter, r *http.Request) (err error) {

	var clientInterface ClientInterface
	var client *BaseClient
	var user *BaseClaim
	var query url.Values
	var claim jwt.MapClaims
	var login, pwd, sess, act string

	isPostMethod := http.MethodPost == r.Method

	authRequest := new(AuthRequest)

	if isPostMethod {
		err = r.ParseForm()
		if err != nil {
			oID.error(Error{Err: "invalid_request", Desc: err.Error()}, "", "", w, r)
			return
		}

		query = r.PostForm
		login = strings.TrimSpace(r.PostForm.Get("login"))
		pwd = strings.TrimSpace(r.PostForm.Get("password"))
	} else {
		query = r.URL.Query()
	}

	authRequest.parse(query)
	act = strings.TrimSpace(query.Get("act"))
	sess = strings.TrimSpace(query.Get("sess"))

	clientInterface, err = oID.storage.GetClientById(provider, authRequest.ClientId)
	if err != nil {
		oID.error(Error{Err: "server_error", Desc: err.Error()}, authRequest.RedirectUri, authRequest.State, w, r)
		return
	}

	if clientInterface == nil {
		oID.error(Error{Err: "unauthorized_client", Desc: "unauthorized_client"}, authRequest.RedirectUri, authRequest.State, w, r)
		return
	}

	client = clientInterface.GetBaseClient()
	if client == nil {
		oID.error(Error{Err: "unauthorized_client", Desc: "unauthorized_client"}, authRequest.RedirectUri, authRequest.State, w, r)
		return
	}

	// Валидируем параметры запроса
	err = authRequest.validate(client)
	if err != nil {
		oID.error(err, authRequest.RedirectUri, authRequest.State, w, r)
		return
	}

	if authRequest._isPromptNone {

		// Получаем список всех аккаунтов
		current, accounts := oID.getAccounts(provider, authRequest.ClientId, client.Secret, r)

		if current == nil {

			// пробуем с подсказкой
			if len(authRequest.Id_token_hint) == 0 {
				err = Error{Err: "invalid_request", Desc: "Empty session and id_token_hint"}
				return
			}

			// Парсим id_token_hint
			claim, err = oID.parseJWTToken(provider, client.Secret, authRequest.Id_token_hint)
			if err != nil {
				err = Error{Err: "login_required", Desc: "Empty session and id_token_hint"}
				return
			}

			aud, ok := claim["aud"].(string)
			if !ok {
				err = Error{Err: "login_required", Desc: "Empty session"}
				return
			}

			if aud != authRequest.ClientId {
				err = Error{Err: "login_required", Desc: "Empty session"}
				return
			}

			//  Получаем аккаунт
			sub, ok := claim["sub"].(string)
			if !ok {
				err = Error{Err: "login_required", Desc: "Empty session"}
				return
			}

			current = oID.getAccount(sub, authRequest.ClientId, accounts)
			if current == nil {
				err = Error{Err: "login_required", Desc: "Empty session"}
				return
			}

		}

		sub, ok := (*current)["sub"].(string)
		if !ok {
			err = Error{Err: "login_required", Desc: "Empty session"}
			return
		}

		user, err = oID.storage.GetUserBySub(provider, sub)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: err.Error()}, authRequest.RedirectUri, authRequest.State, w, r)
			return
		}

	} else {
		// Если передан логин и пароль, выполняем авторизацию
		if len(login) > 0 && len(pwd) > 0 {
			// Запрашиваем пользователя
			user, err = oID.storage.AuthUser(provider, login, pwd)
			if err != nil {
				oID.error(Error{Err: "server_error", Desc: err.Error()}, authRequest.RedirectUri, authRequest.State, w, r)
				return
			}

			if user != nil {
				authRequest._session_state = oID.setSession(provider, w, user, oID.getIssuer(provider), clientInterface)
			}

		} else {

			// Всегда авторизуем пользователя, выводим форму авторизации
			if authRequest._isPromptLogin {
				oID.tpl.Execute(w, map[string]interface{}{
					"type":  "LOGIN",
					"model": authRequest,
				})
				return nil
			}

			// Необходимо выбрать аккаунт, если не передан
			if authRequest._isPromptSelectAccount {
				_, accounts := oID.getAccounts(provider, authRequest.ClientId, client.Secret, r)
				if len(accounts) == 0 {
					// Выводим форму для ввода пароля
					oID.tpl.Execute(w, map[string]interface{}{
						"type":  "LOGIN",
						"model": authRequest,
					})
					return
				}

				if len(sess) == 0 {
					// Выводим форму выбора
					oID.tpl.Execute(w, map[string]interface{}{
						"accounts": accounts,
						"type":     "SELECT_ACCOUNT",
						"model":    authRequest,
					})
					return nil
				}

				account := oID.getAccountBySession(sess, accounts)
				if account == nil {
					oID.error(Error{Err: "access_denied", Desc: "access_denied"}, authRequest.RedirectUri, authRequest.State, w, r)
					return
				}

				sub, ok := (*account)["sub"].(string)
				if !ok {
					oID.error(Error{Err: "access_denied", Desc: "access_denied"}, authRequest.RedirectUri, authRequest.State, w, r)
					return
				}

				// Получаем юзера
				user, err = oID.storage.GetUserBySub(provider, sub)
				if err != nil {
					oID.error(Error{Err: "server_error", Desc: err.Error()}, authRequest.RedirectUri, authRequest.State, w, r)
					return
				}

				if user != nil {
					authRequest._session_state = oID.setSession(provider, w, user, oID.getIssuer(provider), clientInterface)
				}

			}

			if user == nil {
				oID.tpl.Execute(w, map[string]interface{}{
					"type":  "LOGIN",
					"model": authRequest,
				})
				return nil
			}

		}

		// Юзер найден, необходимо запросить разрешение
		if authRequest._isPromptConsent && !authRequest._isPromptNone {
			if act == "reset" {
				oID.error(Error{Err: "access_denied", Desc: "access_denied"}, authRequest.RedirectUri, authRequest.State, w, r)
				return
			}

			if act != "consent" {
				oID.tpl.Execute(w, map[string]interface{}{
					"type":    "CONSENT",
					"model":   authRequest,
					"session": sess,
				})
				return nil
			}
		}

	}

	if user == nil {
		oID.error(Error{Err: "access_denied", Desc: "access_denied"}, authRequest.RedirectUri, authRequest.State, w, r)
		return
	}

	if err = oID.genAuthCode(provider, clientInterface, authRequest, user); err != nil {
		oID.error(Error{Err: "server_error", Desc: err.Error()}, authRequest.RedirectUri, authRequest.State, w, r)
		return
	}

	// Генерируем id_token
	if err = oID.genIdTokenD(provider, clientInterface, authRequest, user); err != nil {
		oID.error(Error{Err: "server_error", Desc: err.Error()}, authRequest.RedirectUri, authRequest.State, w, r)
		return
	}

	if err = oID.genToken(provider, clientInterface, authRequest, user); err != nil {
		oID.error(Error{Err: "server_error", Desc: err.Error()}, authRequest.RedirectUri, authRequest.State, w, r)
		return
	}

	if authRequest.Response_mode == RESPONSE_TYPE_FORM_POST {
		w.Write(authRequest.getForm())
		return
	} else {
		path := authRequest.getPath()
		http.Redirect(w, r, path, 302)
		return
	}

	return

}

func (oID OpenID) genAuthCode(tenant string, clientInterface ClientInterface, authRequest *AuthRequest, user *BaseClaim) (err error) {
	if authRequest.ResponseType != AUTH_RESPONSE_TYPE_ID_TOKEN && authRequest.ResponseType != AUTH_RESPONSE_TYPE_MULTI_3 {
		// Генерируем только code и сохраняем
		code := Code{
			Id:           genCode(10),
			Redirect_uri: authRequest.RedirectUri,
			Client_id:    clientInterface.GetId(),
			Subject:      user.Sub,
			ExpireAt:     time.Now().Add(10 * time.Minute).Unix(),
			Scopes:       authRequest.Scopes,
		}

		// Ассоциируем для кода access_token
		if err = oID.storage.SetCode(tenant, &code); err != nil {
			return
		}

		authRequest._code = code.Id
	}

	return
}

func (oID *OpenID) genIdTokenD(tenant string, clientInterface ClientInterface, authRequest *AuthRequest, user *BaseClaim) (err error) {
	if authRequest.ResponseType != AUTH_RESPONSE_TYPE_CODE && authRequest.ResponseType != AUTH_RESPONSE_TYPE_MULTI_1 {
		authRequest._id_token, err = oID.genIdToken(tenant, clientInterface, authRequest.Nonce, authRequest.Scopes, user)
	}
	return
}

func (oID *OpenID) genToken(tenant string, clientInterface ClientInterface, authRequest *AuthRequest, user *BaseClaim) (err error) {

	if authRequest.ResponseType == AUTH_RESPONSE_TYPE_MULTI_1 || authRequest.ResponseType == AUTH_RESPONSE_TYPE_MULTI_3 || authRequest.ResponseType == AUTH_RESPONSE_TYPE_MULTI_4 {

		client := clientInterface.GetBaseClient()

		access := AccessToken{
			Id:     genCode(24),
			Aud:    clientInterface.GetId(),
			Sub:    user.Sub,
			Exp:    time.Now().Add(time.Duration(client.Token_timeout) * time.Second).Unix(),
			Iss:    oID.getIssuer(tenant),
			Scopes: authRequest.Scopes,
		}

		err = oID.storage.SetAccessToken(tenant, &access)
		if err != nil {
			return
		}

		authRequest._access_token = access.Id
	}
	return
}

func (oID *OpenID) Userinfo(provider string, w http.ResponseWriter, r *http.Request) {

	token := ""

	oID.setCORS(w, r)

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			oID.error(Error{Err: "invalid_request", Desc: err.Error()}, "", "", w, r)
			return
		}
		token = r.PostForm.Get("access_token")
	} else {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}

	if len(token) == 0 {
		oID.error(Error{Err: "access_denied", Desc: "invalid_token"}, "", "", w, r)
		return
	}

	access_token, err := oID.storage.GetAccessToken(provider, token)
	if err != nil {
		oID.error(Error{Err: "server_error", Desc: err.Error()}, "", "", w, r)
		return
	}

	if access_token == nil {
		oID.error(Error{Err: "access_denied", Desc: "invalid_token"}, "", "", w, r)
		return
	}

	if time.Now().After(time.Unix(access_token.Exp, 0)) {
		oID.error(Error{Err: "access_denied", Desc: "invalid_token"}, "", "", w, r)
		return
	}

	clientInterface, err := oID.storage.GetClientById(provider, access_token.Aud)
	if err != nil {
		oID.error(Error{Err: "server_error", Desc: err.Error()}, "", "", w, r)
		return
	}

	if clientInterface == nil {
		oID.error(Error{Err: "unauthorized_client", Desc: "unauthorized_client"}, "", "", w, r)
		return
	}

	client := clientInterface.GetBaseClient()
	if client == nil {
		oID.error(Error{Err: "unauthorized_client", Desc: "unauthorized_client"}, "", "", w, r)
		return
	}

	user, err := oID.storage.GetUserBySub(provider, access_token.Sub)
	if err != nil {
		oID.error(Error{Err: "server_error", Desc: err.Error()}, "", "", w, r)
		return
	}

	if user == nil {
		oID.error(Error{Err: "access_denied", Desc: "invalid_user"}, "", "", w, r)
		return
	}

	result := jwt.MapClaims{}

	for _, el := range access_token.Scopes {
		if el == "openid" || el == "offline_access" {
			continue
		}

		for _, scope := range client.Scopes {
			if scope.Name == el {
				result[el] = user.Get(scope.Name, scope.Fields)
				continue
			}
		}
	}
	result["sub"] = user.Sub

	oID.sendJson(result, w, 0)

}

func (oID *OpenID) Token(provider string, w http.ResponseWriter, r *http.Request) {

	oID.setCORS(w, r)

	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	tokenRequest := new(TokenRequest)
	var err error

	err = r.ParseForm()
	if err != nil {
		oID.error(Error{Err: "invalid_request", Desc: err.Error()}, "", "", w, r)
		return
	}

	tokenRequest.parseForm(r.PostForm)

	client_id, client_secret, authOK := r.BasicAuth()
	if authOK == false {
		// Проверяем другие типы
		// TODO добавить поддержку client_secret_jwt, private_key_jwt, none
		client_id = tokenRequest.client_id
		client_secret = tokenRequest.client_secret
	}

	if len(client_id) == 0 || len(client_secret) == 0 {
		oID.error(Error{Err: "unauthorized_client", Desc: "unauthorized_client"}, tokenRequest.redirect_uri, "", w, r)
		return
	}

	clientInterface, err := oID.storage.GetClientById(provider, client_id)
	if err != nil {
		oID.error(Error{Err: "server_error", Desc: err.Error()}, tokenRequest.redirect_uri, "", w, r)
		return
	}

	if clientInterface == nil {
		oID.error(Error{Err: "unauthorized_client", Desc: "unauthorized_client"}, tokenRequest.redirect_uri, "", w, r)
		return
	}

	client := clientInterface.GetBaseClient()

	if client == nil {
		oID.error(Error{Err: "unauthorized_client", Desc: "unauthorized_client"}, "", "", w, r)
		return
	}

	if client.Secret != client_secret {
		oID.error(Error{Err: "unauthorized_client", Desc: "unauthorized_client"}, "", "", w, r)
		return
	}

	if err = tokenRequest.validate(); err != nil {
		oID.error(Error{Err: "invalid_request", Desc: err.Error()}, "", "", w, r)
		return
	}

	// Запрос токенов
	if tokenRequest.grant_type == GRANT_TYPE_AUTH_CODE {

		code, err := oID.storage.GetCode(provider, tokenRequest.code)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: "server_error"}, "", "", w, r)
			return
		}

		if code == nil {
			oID.error(Error{Err: "invalid_request", Desc: "invalid_request"}, "", "", w, r)
			return
		}

		if clientInterface.GetId() != code.Client_id {
			oID.error(Error{Err: "invalid_request", Desc: "invalid_request"}, "", "", w, r)
			return
		}

		if len(client.Redirect_uris) > 1 && len(tokenRequest.redirect_uri) == 0 {
			oID.error(Error{Err: "invalid_request", Desc: "invalid_request"}, "", "", w, r)
			return
		}

		if len(tokenRequest.redirect_uri) > 0 && tokenRequest.redirect_uri != code.Redirect_uri {
			oID.error(Error{Err: "invalid_request", Desc: "invalid_request"}, tokenRequest.redirect_uri, "", w, r)
			return
		}

		if time.Now().After(time.Unix(code.ExpireAt, 0)) {
			oID.error(Error{Err: "invalid_request", Desc: "invalid_request"}, tokenRequest.redirect_uri, "", w, r)
			return
		}

		data := map[string]interface{}{
			"token_type": "Bearer",
			"expires_in": client.Token_timeout,
		}

		// Генерируем access_token
		access := AccessToken{
			Id:     genCode(32),
			Aud:    clientInterface.GetId(),
			Sub:    code.Subject,
			Exp:    time.Now().Add(time.Duration(client.Token_timeout) * time.Second).Unix(),
			Iss:    oID.getIssuer(provider),
			Scopes: code.Scopes,
		}

		data["access_token"] = access.Id
		data["expires_on"] = access.Exp

		err = oID.storage.SetAccessToken(provider, &access)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: err.Error()}, tokenRequest.redirect_uri, "", w, r)
			return
		}

		user, err := oID.storage.GetUserBySub(provider, code.Subject)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: err.Error()}, tokenRequest.redirect_uri, "", w, r)
			return
		}

		if user == nil {
			oID.error(Error{Err: "invalid_request", Desc: "invalid_request"}, tokenRequest.redirect_uri, "", w, r)
			return
		}

		// Генерируем id_token
		data["id_token"], err = oID.genIdToken(provider, clientInterface, "", code.Scopes, user)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: err.Error()}, tokenRequest.redirect_uri, "", w, r)
			return
		}

		// Генерируем refresh token
		for _, scope := range code.Scopes {
			if scope == "offline_access" {

				token := RefreshToken{
					Id:          genCode(32),
					AccessToken: access.Id,
					Expire:      time.Now().Add(time.Duration(client.Refresh_timeout) * time.Second).Unix(),
					ClientId:    clientInterface.GetId(),
					Subject:     code.Subject,
					Scopes:      code.Scopes,
				}

				err = oID.storage.SetRefreshToken(provider, &token)
				if err != nil {
					oID.error(Error{Err: "server_error", Desc: "server_error"}, "", "", w, r)
					return
				}
				data["refresh_token"] = token.Id
				break
			}
		}

		// Удаляем authorize_code
		err = oID.storage.ClearCode(provider, tokenRequest.code)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: "server_error"}, "", "", w, r)
			return
		}

		oID.sendJson(data, w, 200)
	} else {

		// Получаем refresh
		refresh_token, err := oID.storage.GetRefreshToken(provider, tokenRequest.refresh_token)
		if err != nil {
			oID.error(Error{Err: "invalid_request", Desc: err.Error()}, "", "", w, r)
			return
		}

		if refresh_token == nil {
			oID.error(Error{Err: "invalid_request", Desc: "invalid_refresh_token"}, "", "", w, r)
			return
		}

		// проверяем что не истек
		if time.Now().After(time.Unix(refresh_token.Expire, 0)) {
			oID.error(Error{Err: "invalid_request", Desc: "refresh_token_expired"}, "", "", w, r)
			return
		}

		// Проверяем клиентов
		if clientInterface.GetId() != refresh_token.ClientId {
			oID.error(Error{Err: "invalid_request", Desc: "invalid_client"}, "", "", w, r)
			return
		}

		// Удаляем refresh_token и access_token
		err = oID.storage.DelRefreshToken(provider, refresh_token.Id)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: err.Error()}, "", "", w, r)
			return
		}

		err = oID.storage.DelAccessToken(provider, refresh_token.AccessToken)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: err.Error()}, "", "", w, r)
			return
		}

		// Создаем новый access_token
		access := AccessToken{
			Id:     genCode(32),
			Aud:    clientInterface.GetId(),
			Sub:    refresh_token.Subject,
			Exp:    time.Now().Add(time.Duration(client.Token_timeout) * time.Second).Unix(),
			Iss:    oID.getIssuer(provider),
			Scopes: refresh_token.Scopes,
		}

		err = oID.storage.SetAccessToken(provider, &access)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: err.Error()}, "", "", w, r)
			return
		}

		// Генерируем refresh_token
		token := RefreshToken{
			Id:          genCode(32),
			AccessToken: access.Id,
			Expire:      time.Now().Add(time.Duration(client.Refresh_timeout) * time.Second).Unix(),
			ClientId:    clientInterface.GetId(),
			Subject:     refresh_token.Subject,
			Scopes:      refresh_token.Scopes,
		}

		err = oID.storage.SetRefreshToken(provider, &token)
		if err != nil {
			oID.error(Error{Err: "server_error", Desc: err.Error()}, "", "", w, r)
			return
		}

		data := map[string]interface{}{
			"access_token":  access.Id,
			"token_type":    "Bearer",
			"refresh_token": token.Id,
			"expires_in":    access.Exp,
		}

		oID.sendJson(data, w, 200)

	}

}

func (oID OpenID) Jwks(tenant string, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json")
	oID.sendJson(map[string]interface{}{
		"keys": oID.publicKeys,
	}, w, 0)
}

func (oID *OpenID) Discovery(tenant string, w http.ResponseWriter, r *http.Request) {

	w.Header().Add("content-type", "application/json")
	oID.send(w, oID.settings.toJSON(tenant))

	/*

			{
		   "issuer": "https://server.example.com",
		   "authorization_endpoint": "https://server.example.com/connect/authorize",
		   "token_endpoint": "https://server.example.com/connect/token",

		   "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],

		    "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],

		   "userinfo_endpoint": "https://server.example.com/connect/userinfo",

		   "check_session_iframe": "https://server.example.com/connect/check_session",
		   "end_session_endpoint": "https://server.example.com/connect/end_session",

		   "jwks_uri": "https://server.example.com/jwks.json",

		   "registration_endpoint": "https://server.example.com/connect/register",

		   "scopes_supported":  ["openid", "profile", "email", "address", "phone", "offline_access"],
		   "response_types_supported":  ["code", "code id_token", "id_token", "token id_token"],

		   "acr_values_supported": ["urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"],
		   "subject_types_supported": ["public", "pairwise"],
		   "userinfo_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
		   "userinfo_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
		   "userinfo_encryption_enc_values_supported": ["A128CBC-HS256", "A128GCM"],
		   "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
		   "id_token_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
		   "id_token_encryption_enc_values_supported": ["A128CBC-HS256", "A128GCM"],
		   "request_object_signing_alg_values_supported": ["none", "RS256", "ES256"],
		   "display_values_supported": ["page", "popup"],
		   "claim_types_supported": ["normal", "distributed"],
		   "claims_supported": ["sub", "iss", "auth_time", "acr", "name", "given_name", "family_name", "nickname", "profile", "picture", "website", "email", "email_verified", "locale", "zoneinfo", "http://example.info/claims/groups"],
		   "claims_parameter_supported": true,
		   "service_documentation": "http://server.example.com/connect/service_documentation.html",
		   "ui_locales_supported": ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
		  }

	*/
}

func (oID *OpenID) Logout(tenant string, w http.ResponseWriter, r *http.Request) {
	oID.setCORS(w, r)
	var query url.Values

	old := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)

	isPostMethod := http.MethodPost == r.Method

	logoutRequest := new(LogoutRequest)

	if isPostMethod {
		err := r.ParseForm()
		if err != nil {
			oID.error(Error{Err: "invalid_request", Desc: err.Error()}, "", "", w, r)
			return
		}

		query = r.PostForm
	} else {
		query = r.URL.Query()
	}

	logoutRequest.parse(query)

	var curr *http.Cookie
	// Получим id текущей сессии
	currSessName := ""
	c, _ := r.Cookie("session")
	if c != nil {
		currSessName = c.Value
		curr, _ = r.Cookie(currSessName)
	}

	if !logoutRequest.isExistIdToken {
		if curr != nil {

			// Читаем куку
			claim, err := oID.readJWTToken(tenant, curr.Value)
			if err != nil {
				oID.error(Error{Err: "invalid_request", Desc: err.Error()}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
				return
			}

			aud, ok := claim["aud"].(string)
			if !ok {
				oID.error(Error{Err: "invalid_request", Desc: "Invalid claim aud"}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
				return
			}
			clientInterface, err := oID.storage.GetClientById(tenant, aud)
			if err != nil {
				oID.error(Error{Err: "invalid_request", Desc: err.Error()}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
				return
			}

			if clientInterface == nil {
				oID.error(Error{Err: "invalid_request", Desc: "Invalid client"}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
				return
			}

			client := clientInterface.GetBaseClient()
			if client == nil {
				oID.error(Error{Err: "invalid_request", Desc: "Invalid client"}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
				return
			}

			// Валидируем url
			claim, err = oID.parseJWTToken(tenant, client.Secret, curr.Value)
			if err != nil {
				oID.error(Error{Err: "invalid_request", Desc: err.Error()}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
				return
			}

			err = logoutRequest.validate(client)
			if err != nil {
				oID.error(Error{Err: "invalid_request", Desc: err.Error()}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
				return
			}

			curr.Expires = old
			c.Expires = old
			http.SetCookie(w, curr)
			http.SetCookie(w, c)
		}
	} else {
		// читаем токен
		res, err := oID.readJWTToken(tenant, logoutRequest.id_token_hint)
		if err != nil {
			oID.error(Error{Err: "invalid_request", Desc: err.Error()}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
			return
		}

		aud, ok := res["aud"].(string)
		if !ok {
			oID.error(Error{Err: "invalid_request", Desc: "Invalid claim aud"}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
			return
		}

		sub, ok := res["sub"].(string)
		if !ok {
			oID.error(Error{Err: "invalid_request", Desc: "Invalid claim subject"}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
			return
		}

		clientInterface, err := oID.storage.GetClientById(tenant, aud)
		if err != nil {
			oID.error(Error{Err: "invalid_request", Desc: err.Error()}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
			return
		}

		if clientInterface == nil {
			oID.error(Error{Err: "invalid_request", Desc: "Invalid client"}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
			return
		}

		client := clientInterface.GetBaseClient()
		if client == nil {
			oID.error(Error{Err: "invalid_request", Desc: "Invalid client"}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
			return
		}

		_, err = oID.parseJWTToken(tenant, client.Secret, logoutRequest.id_token_hint)
		if err != nil {
			oID.error(Error{Err: "invalid_request", Desc: err.Error()}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
			return
		}

		err = logoutRequest.validate(client)
		if err != nil {
			oID.error(Error{Err: "invalid_request", Desc: err.Error()}, logoutRequest.post_logout_redirect_uri, logoutRequest.state, w, r)
			return
		}

		// Получаем все куки
		cookies := r.Cookies()

		for _, cookie := range cookies {
			res, err := oID.readJWTToken(tenant, cookie.Value)
			if err != nil {
				continue
			}

			client_id, ok := res["aud"]
			if !ok {
				continue
			}

			user_id, ok := res["sub"]
			if !ok {
				continue
			}

			if client_id != aud {
				continue
			}

			if sub != user_id {
				continue
			}

			if currSessName == cookie.Name {
				c.Expires = old
				http.SetCookie(w, c)
			}

			cookie.Expires = old
			http.SetCookie(w, cookie)
		}

	}

	// Редиректим или выводим сообщение
	if len(logoutRequest.post_logout_redirect_uri) > 0 {
		http.Redirect(w, r, logoutRequest.post_logout_redirect_uri, 301)
	} else {
		oID.tpl.Execute(w, map[string]interface{}{
			"type":  "LOGOUT_SUCCESS",
			"model": logoutRequest,
		})
	}

	return
}

func (oID *OpenID) Registration(tenant string, w http.ResponseWriter, r *http.Request) {

	if oID.settings.enabled_access_control {
		accessToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, err := oID.storage.GetGlobalAccessToken(tenant)
		if err != nil {
			oID.sendJson(Error{Err: "internal_error", Desc: err.Error()}, w, 500)
			return
		}

		if accessToken != token {
			w.WriteHeader(401)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Invalid token"`)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			return
		}
	}


	switch r.Method {
	case http.MethodDelete:
		oID.removeClient(tenant, w, r)
		break
	case http.MethodPost:
		if len(r.URL.Query().Get("client_id")) > 0 {
			oID.updateClient(tenant, w, r)
		} else {
			oID.createClient(tenant, w, r)
		}
		break
	case http.MethodGet:
		if len(r.URL.Query().Get("client_id")) > 0 {
			oID.getClient(tenant, w, r)
		} else {
			oID.getClients(tenant, w, r)
		}

		break
	default:
		oID.sendJson(Error{Err: "internal_error", Desc: "Not implemented yet"}, w, 500)
		return
	}

	return
}

func (oID *OpenID) updateClient(tenant string, w http.ResponseWriter, r *http.Request) {

	data, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		oID.sendJson(Error{Err: "invalid_client_metadata", Desc: err.Error()}, w, 400)
		return
	}

	client_id := r.URL.Query().Get("client_id")

	// Получаем старого клиента
	oldClientInterface, err := oID.storage.GetClientById(tenant, client_id)
	if err != nil {
		oID.sendJson(Error{Err: "internal_error", Desc: err.Error()}, w, 500)
		return
	}

	if oldClientInterface == nil {
		oID.sendJson(Error{Err: "invalid_token", Desc: "Invalid token or client_id"}, w, 401)
		return
	}

	oldClient := oldClientInterface.GetBaseClient()
	if oldClient == nil {
		oID.sendJson(Error{Err: "invalid_token", Desc: "Invalid token or client_id"}, w, 401)
		return
	}

	serviceApi := struct {
		Generate_token bool `json:"generate_token"`
	}{}

	err = json.Unmarshal(data, &serviceApi)
	if err != nil {
		oID.sendJson(Error{Err: "invalid_client_metadata", Desc: err.Error()}, w, 400)
		return
	}

	client := BaseClient{
		Contacts: make([]string,0),
		Scopes: make([]*ClientScope, 0),
	}
	err = json.Unmarshal(data, &client)
	if err != nil {
		oID.sendJson(Error{Err: "invalid_client_metadata", Desc: err.Error()}, w, 400)
		return
	}

	// Валидируем клиента
	err = client.validate()
	if err != nil {
		oID.sendJson(Error{Err: "invalid_client_metadata", Desc: err.Error()}, w, 400)
		return
	}

	// Присваиваем secret от старого
	if serviceApi.Generate_token {
		client.Secret = genCode(64)
	} else {
		client.Secret = oldClient.Secret
	}

	err = oID.storage.UpdateClient(tenant, client_id, &client)
	if err != nil {
		oID.sendJson(Error{Err: "internal_error", Desc: err.Error()}, w, 500)
		return
	}

	oID.sendJson(map[string]interface{}{
		"error": false,
	}, w, 200)

}

func (oID *OpenID) removeClient(tenant string, w http.ResponseWriter, r *http.Request) {

	client_id := r.URL.Query().Get("client_id")
	if len(client_id) == 0 {
		oID.sendJson(Error{Err: "invalid_client_metadata", Desc: "Invalid client_id"}, w, 400)
		return
	}

	if err := oID.storage.RemoveClient(tenant, client_id); err != nil {
		oID.sendJson(Error{Err: "internal_error", Desc: err.Error()}, w, 500)
		return
	}

	oID.sendJson(map[string]interface{}{
		"error": false,
	}, w, 200)
}

func (oID *OpenID) getClients(tenant string, w http.ResponseWriter, r *http.Request) {

	clients, err := oID.storage.GetClients(tenant)
	if err != nil {
		oID.sendJson(Error{Err: "internal_error", Desc: err.Error()}, w, 500)
		return
	}

	oID.sendJson(clients, w, 200)
}

func (oID *OpenID) getClient(tenant string, w http.ResponseWriter, r *http.Request) {

	client, err := oID.storage.GetClientById(tenant, r.URL.Query().Get("client_id"))
	if err != nil {
		oID.sendJson(Error{Err: "internal_error", Desc: err.Error()}, w, 500)
		return
	}

	if client == nil {
		oID.sendJson(Error{Err: "invalid_token", Desc: "Invalid token"}, w, 401)
		return
	}

	oID.sendJson(client, w, 201)
}

func (oID *OpenID) createClient(tenant string, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	if err != nil {
		oID.sendJson(Error{Err: "invalid_client_metadata", Desc: err.Error()}, w, 400)
		return
	}

	client := BaseClient{
		Contacts: make([]string,0),
		Scopes: make([]*ClientScope, 0),
	}
	err = json.Unmarshal(data, &client)
	if err != nil {
		oID.sendJson(Error{Err: "invalid_client_metadata", Desc: err.Error()}, w, 400)
		return
	}

	// Валидируем клиента
	err = client.validate()
	if err != nil {
		oID.sendJson(Error{Err: "invalid_client_metadata", Desc: err.Error()}, w, 400)
		return
	}

	// Генерируем ключ
	client.genSecret()

	result, err := oID.storage.CreateClient(tenant, &client)
	if err != nil {
		oID.sendJson(Error{Err: "internal_error", Desc: err.Error()}, w, 500)
		return
	}

	oID.sendJson(result, w, 201)
}

func (oID *OpenID) EnableAccesControl() {
	oID.settings.enabled_access_control = true
}