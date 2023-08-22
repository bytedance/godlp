package dlp

import (
	"encoding/json"
	"testing"
)

func Test_decodeJson(t *testing.T) {
	jsonText := `{"id":146310743121612001}`
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(jsonText), &jsonObj); err != nil {
		t.Error(err)
		return
	}
	t.Logf("json.Unmarshal result:%v", jsonObj) //146310743121612000

	err := decodeJson([]byte(jsonText), &jsonObj)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("decodeJson result:%v", jsonObj) //146310743121612001
}
