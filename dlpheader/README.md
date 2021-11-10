# dlpheader 介绍

dlpheader定义了DLP SDK需要的数据结构，常量定义等。DLP SDK主要提供了以下API进行敏感信息识别和脱敏。

1. ApplyConfig(conf string) error
- ApplyConfig by configuration content
- 传入conf string 进行配置

2. ApplyConfigFile(filePath string) error
- ApplyConfigFile by config file path
- 传入filePath 进行配置

3. Detect(inputText string) ([]*DetectResult, error)
- Detect string
- 对string进行敏感信息识别

4. DetectMap(inputMap map[string]string) ([]*DetectResult, error)
- DetectMap detects KV map
- 对map[string]string进行敏感信息识别

5. DetectJSON(jsonText string) ([]*DetectResult, error)
- DetectJSON detects json string
- 对json string 进行敏感信息识别

6. Deidentify(inputText string) (string, []*DetectResult, error)
- Deidentify detects string firstly, then return masked string and results
- 对string先识别，然后按规则进行打码

7. DeidentifyMap(inputMap map[string]string) (map[string]string, []*DetectResult, error)
- DeidentifyMap detects KV map firstly,then return masked map
- 对map[string]string先识别，然后按规则进行打码

8. ShowResults(resultArray []*DetectResult)
- ShowResults print results in console
- 打印识别结果

9. Mask(inputText string, methodName string) (string, error)
- Mask inputText following predefined method of MaskRules in config
- 根据脱敏规则直接脱敏

10. Close()
- Close engine object, release memory of inner object
- 关闭，释放内部变量

11. GetVersion() string
- Get Dlp SDK version string
- 获取版本号

12. RegisterMasker(maskName string, maskFunc func(string) (string, error)) error
- Register DIY Masker
- 注册自定义打码函数

13. NewLogProcesser() logs.Processor
- NewLogProcesser create a log processer for the package logs
- 日志脱敏处理函数

14. MaskStruct(inObj interface{}) (interface{}, error)
- MaskStruct will mask a strcut object by tag mask info
- 根据tag mask里定义的脱敏规则对struct object直接脱敏

	
	
