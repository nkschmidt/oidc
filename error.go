package OpenID

import (
	"encoding/json"
	"strings"
)

type Error struct {
	Err       string `json:"error"`
	Desc      string `json:"error_description"`
	rawValues []string
}

func (e Error) Error() string {
	return e.Err
}

func (e Error) query() string {
	return "?error=" + e.Err + "&error_description=" + e.Desc + "&" + strings.Join(e.rawValues, "&")
}

func (e Error) toJSON() []byte {
	data := map[string]interface{}{
		"error":             e.Err,
		"error_description": e.Desc,
	}

	for _, item := range e.rawValues {
		val := strings.Split(item, "=")
		data[val[0]] = val[1]
	}

	bt, _ := json.Marshal(data)

	return bt
}

func (e *Error) include(key, val string) {
	if len(val) > 0 {
		e.rawValues = append(e.rawValues, key+"="+val)
	}
}
