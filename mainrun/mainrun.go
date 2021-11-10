package main

import (
	"bytes"
	"fmt"
	dlp "github.com/bytedance/godlp"
	"github.com/bytedance/godlp/dlpheader"
	"strings"
)

func dupString(src string, coefficient int) string {
	var buffer bytes.Buffer
	for i := 0; i < coefficient; i++ {
		buffer.WriteString(src)
	}
	return buffer.String()
}

func dlpDemo() {
	caller := "replace.your.caller"
	// 使用时请将NewEngine()放到循环外，每个线程独立一个Engine Object
	// remove NewEngein() outside for loop, and one Engine Object one thread/goroutin
	if eng, err := dlp.NewEngine(caller); err == nil {
		eng.ApplyConfigDefault()
		fmt.Printf("DLP %s Demo:\n\n", eng.GetVersion())
		inStr := `我的邮件是abcd@abcd.com,
18612341234是我的电话
你家住在哪里啊? 我家住在北京市海淀区北三环西路43号,
mac地址 06-06-06-aa-bb-cc
收件人：张真人  手机号码：18612341234`
		if results, err := eng.Detect(inStr); err == nil {
			fmt.Printf("\t1. Detect( inStr: %s )\n", inStr)
			eng.ShowResults(results)
		}
		if outStr, _, err := eng.Deidentify(inStr); err == nil {
			fmt.Printf("\t2. Deidentify( inStr: %s )\n", inStr)
			fmt.Printf("\toutStr: %s\n", outStr)
			//eng.ShowResults(results)
			fmt.Println()
		}
		inStr = `18612341234`
		if outStr, err := eng.Mask(inStr, dlpheader.CHINAPHONE); err == nil {
			fmt.Printf("\t3. Mask( inStr: %s )\n", inStr)
			fmt.Printf("\toutStr: %s\n", outStr)
			fmt.Println()
		}

		inMap := map[string]string{"nothing": "nothing", "uid": "10086", "k1": "my phone is 18612341234 and 18612341234"} // extract KV?

		if results, err := eng.DetectMap(inMap); err == nil {
			fmt.Printf("\t4. DetectMap( inMap: %+v )\n", inMap)
			eng.ShowResults(results)
		}

		fmt.Printf("\t5. DeidentifyMap( inMap: %+v )\n", inMap)
		if outMap, results, err := eng.DeidentifyMap(inMap); err == nil {
			fmt.Printf("\toutMap: %+v\n", outMap)
			eng.ShowResults(results)
			fmt.Println()
		}

		inJSON := `{"objList":[{"uid":"10086"},{"uid":"[\"aaaa\",\"bbbb\"]"}]}`

		if results, err := eng.DetectJSON(inJSON); err == nil {
			fmt.Printf("\t6. DetectJSON( inJSON: %s )\n", inJSON)
			eng.ShowResults(results)
		}

		if outJSON, results, err := eng.DeidentifyJSON(inJSON); err == nil {
			fmt.Printf("\t7. DeidentifyJSON( inJSON: %s )\n", inJSON)
			fmt.Printf("\toutJSON: %s\n", outJSON)
			eng.ShowResults(results)
			fmt.Println()
		}
		inStr = "abcd@abcd.com"
		maskRule := "EmailMaskRule01"
		if outStr, err := eng.Mask(inStr, maskRule); err == nil {
			fmt.Printf("\t8. Mask( inStr: %s , %s)\n", inStr, maskRule)
			fmt.Printf("\toutStr: %s\n", outStr)
			fmt.Println()
		}
		// 自定义脱敏，邮箱用户名保留首尾各一个字符，保留所有域名
		eng.RegisterMasker("EmailMaskRule02", func(in string) (string, error) {
			list := strings.Split(in, "@")
			if len(list) >= 2 {
				prefix := list[0]
				domain := list[1]
				if len(prefix) > 2 {
					prefix = "*" + prefix[1:len(prefix)-1] + "*"
				} else if len(prefix) > 0 {
					prefix = "*" + prefix[1:]
				} else {
					return in, fmt.Errorf("%s is not Email", in)
				}
				ret := prefix + "@" + domain
				return ret, nil
			} else {
				return in, fmt.Errorf("%s is not Email", in)
			}
		})
		inStr = "abcd@abcd.com"
		maskRule = "EmailMaskRule02"
		if outStr, err := eng.Mask(inStr, maskRule); err == nil {
			fmt.Printf("\t9. Mask( inStr: %s , %s)\n", inStr, maskRule)
			fmt.Printf("\toutStr: %s\n", outStr)
			fmt.Println()
		}

		inStr = "loginfo:[ uid:10086, phone:18612341234]"
		if outStr, results, err := eng.Deidentify(inStr); err == nil {
			fmt.Printf("\t10. Detect( inStr: %s )\n", inStr)
			eng.ShowResults(results)
			fmt.Printf("\toutStr: %s\n", outStr)
			fmt.Println()
		}
		type EmailType string
		// 需要递归的结构体，需要填 `mask:"DEEP"` 才会递归脱敏
		type Foo struct {
			Email         EmailType `mask:"EMAIL"`
			PhoneNumber   string    `mask:"CHINAPHONE"`
			Idcard        string    `mask:"CHINAID"`
			Buffer        string    `mask:"DEIDENTIFY"`
			EmailPtrSlice []*struct {
				Val string `mask:"EMAIL"`
			} `mask:"DEEP"`
			PhoneSlice []string `mask:"CHINAPHONE"`
			Extinfo    *struct {
				Addr string `mask:"ADDRESS"`
			} `mask:"DEEP"`
			EmailArray [2]string   `mask:"EMAIL"`
			NULLPtr    *Foo        `mask:"DEEP"`
			IFace      interface{} `mask:"ExampleTAG"`
		}
		var inObj = Foo{
			"abcd@abcd.com",
			"18612341234",
			"110225196403026127",
			"我的邮件是abcd@abcd.com",
			[]*struct {
				Val string `mask:"EMAIL"`
			}{{"3333@4444.com"}, {"5555@6666.com"}},
			[]string{"18612341234", ""},
			&struct {
				Addr string "mask:\"ADDRESS\""
			}{"北京市海淀区北三环西路43号"},
			[2]string{"abcd@abcd.com", "3333@4444.com"},
			nil,
			"abcd@abcd.com",
		}
		inPtr := &inObj
		inObj.NULLPtr = inPtr
		fmt.Printf("\t11. MaskStruct( inPtr: %+v, Extinfo: %+v)\n", inPtr, *(inPtr.Extinfo))
		// MaskStruct 参数必须是pointer, 才能修改struct 内部元素
		if outPtr, err := eng.MaskStruct(inPtr); err == nil {
			fmt.Printf("\toutObj: %+v, Extinfo:%+v\n", outPtr, inObj.Extinfo)
			fmt.Printf("\t\t EmailPtrSlice:\n")
			for i, ePtr := range inObj.EmailPtrSlice {
				fmt.Printf("\t\t\t[%d] = %s\n", i, ePtr.Val)
			}
			fmt.Println()
		} else {
			fmt.Println(err.Error())
		}
		//fmt.Println(eng.GetDefaultConf())
		eng.Close()
	} else {
		fmt.Println("[dlp] NewEngine error: ", err.Error())
	}
}

func main() {
	dlpDemo()
}
