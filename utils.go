package OpenID

import (
	"strings"
	"net/url"
)

func genCode(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return strings.ToLower(string(b))
}

func urlDecode(str string) (string, error) {
	str, err := url.QueryUnescape(str)
	if err != nil {
		return "", err
	}
	
	return str, nil
}

func urlEncode(str string) (string, error) {
	u, err := url.Parse(str)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
