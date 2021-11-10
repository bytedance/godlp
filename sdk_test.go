package dlp

import (
	"io/ioutil"
	"os"
	"runtime"
	"testing"

	"github.com/bytedance/godlp/log"
	"gopkg.in/yaml.v2"
)

type RuleTestItem struct {
	RuleID int32  `yaml:"RuleID"`
	In     string `yaml:"In"`
	Out    string `yaml:"Out"`
}
type RuleTest struct {
	Date     string         `yaml:"Date"`
	TestList []RuleTestItem `yaml:"TestList"`
}

// public func
func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}
func TestRule(t *testing.T) {
	testPath := "./test/rule_test.yml"
	if buf, err := ioutil.ReadFile(testPath); err == nil {
		ruleTestPtr := new(RuleTest)
		if err := yaml.Unmarshal(buf, ruleTestPtr); err == nil {
			t.Logf("%s: Data:%s", testPath, ruleTestPtr.Date)
			if eng, err := NewEngine("replace.your.psm"); err == nil {
				eng.ApplyConfigDefault()
				for _, item := range ruleTestPtr.TestList {
					if out, results, err := eng.Deidentify(item.In); err == nil {
						if len(results) == 0 && item.RuleID == 0 { // no sensitive info found, it's ok
							// check ok
							continue
						}
						if out == item.Out && len(results) >= 1 && results[0].RuleID == item.RuleID { // check ok
							// check ok
							continue
						} else {
							resultId := int32(-1)
							if len(results) >= 1 {
								resultId = results[0].RuleID
							}
							t.Errorf("Error RuleId: %d, in: %s, out: %s, Deidentify: %s, Results RuleId: %d", item.RuleID, item.In, item.Out, out, resultId)
							eng.ShowResults(results)
						}
					} else {
						t.Error(err.Error())
					}

				}
				t.Logf("Total %d Rule Test Case pass", len(ruleTestPtr.TestList))
			} else {
				t.Error(err)
			}

		} else {
			t.Error(err)
		}
	} else {
		t.Error(err)
	}
}

// private func

func setup() {
	runtime.GOMAXPROCS(1)
	log.SetLevel(log.LevelError)
}

func shutdown() {

}
