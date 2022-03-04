package dlp

import (
	"encoding/json"
	"testing"
)

var (
	numericJsonTextTestCases = []struct {
		jsonText  string
		wantKey   string
		wantValue string
	}{
		{`{"int":200}`, "/int", "200"},
		{`{"float_list":[11.111111]}`, "/float_list[0]", "11.111111"},
		{`{"int_list":[1]}`, "/int_list[0]", "1"},
		{`{"max_float":1.7976931348623157E+308}`, "/max_float", "1.7976931348623157e+308"},
		{`{"negative_float":-1.7976931348623157E+308}`, "/negative_float", "-1.7976931348623157e+308"},
		{`{"negative_int":-1}`, "/negative_int", "-1"},
		{`{"string":"moond4rk"}`, "/string", "moond4rk"},
	}
)

func TestEngine_dfsJSON(t *testing.T) {
	I := new(Engine)
	for _, tc := range numericJsonTextTestCases {
		var jsonObj interface{}
		if err := json.Unmarshal([]byte(tc.jsonText), &jsonObj); err == nil {
			kvMap := make(map[string]string, 0)
			I.dfsJSON("", &jsonObj, kvMap, false)
			if len(kvMap) == 0 {
				t.Errorf("%s: no key-value pairs found", tc.jsonText)
			}
			for key, value := range kvMap {
				if key != tc.wantKey {
					t.Errorf("key: %s, wantKey: %s", key, tc.wantKey)
				}
				if value != tc.wantValue {
					t.Errorf("value: %s, wantValue: %s", value, tc.wantValue)
				}
			}
		}
	}
}
