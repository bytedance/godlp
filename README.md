# godlp

# 一、简介

为了保障企业的数据安全和隐私安全，godlp 提供了一系列针对敏感数据的识别和处置方案，
其中包括敏感数据识别算法，数据脱敏处理方式，业务自定义的配置选项和海量数据处理能力。
godlp 能够应用多种隐私合规标准，对原始数据进行分级打标、判断敏感级别和实施相应的脱敏处理。

In order to achieve data security and privacy security requirements for enterprises,
godlp provides a serial of sensitive information finding and handling methods,
including sensitive detection algorithm, de-identification APIs, business DIY configuration and the big data handling ability.
Also, godlp is able to apply a variety of privacy compliance standers, do classification based on sensitive levels, and mask data based on rules.

# 二、关键能力

godlp 能够广泛支持结构化（JSON数据、KV数据、golang map）和非结构化数据（多语言字符串）。

## 1. 敏感数据自动发现
   DLP 内置多种敏感数据识别规则，能对原始数据进行敏感类型识别，确保敏感信息能被妥善处理。
## 2. 敏感数据脱敏处理
   DLP 支持多种脱敏算法，业务可以根据需求对敏感数据进行不同的脱敏处理。
## 3. 业务自定义配置选项
   除默认的敏感信息识别和处理规则外，业务可以根据实际情况，配置自定义的YAML规则，DLP 能够根据传入的配置选项，完成相应的数据处理任务。

# 三、接入方式

```shell
go get github.com/bytedance/godlp@latest
```

示例代码在 `mainrun/mainrun.go` 文件中

在godlp代码根目录下输入以下命令可以进行编译和运行

```shell
make
make run
make test
make bench
```

## API 描述

dlpheader定义了 godlp SDK需要的数据结构，常量定义等。godlp SDK主要提供了以下API进行敏感信息识别和脱敏。

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

# 四、规则文件

规则文件请见 `conf.yml`

config 文件以yaml格式为准，整体分为: `Global`,`MaskRules`,`Rules` 三个部分。其中：
1. Global
    包含影响DLP全局的一些配置项，例如API版本、禁用的规则ID、是否启用后端服务辅助判断。
2. MaskRules
   包含脱敏操作的配置，例如打码、替换等方式。
3. Rules
   包含识别和处理规则，其中一个识别过程包括 Detect, Filter 和 Verify 三个依次的过程， 处理需要引用上面定义的脱敏规则。

# 五、架构

godlp 以 Engine 结构为主，通过Engine对象来实现 EngineAPI 接口，直接实现的接口以`sdk.go`,`sdkdeidentify.go`,`sdkdetect.go`和`sdkmask.go`为主。对于deidentify和mask操作，会继续调用子目录下的`detector`,`mask`子模块。

## 5.1 文件说明

1. sdk.go: 实现EngineAPI接口中业务无关的API，例如Close()

2. sdk_test.go: 单元测试用例。

3. sdkconfig.go: 实现配置相关的接口，例如ApplyConfig()

4. sdkdeidentify.go: 实现脱敏相关的接口。

5. sdkdetect.go: 实现敏感信息检测接口。

6. sdkinternal.go: 实现 Engine 对象的内部函数。

7. sdkmask.go: 实现直接打码的接口。

8. conf.yml: 内置的默认配置文件，含DLP维护的规则。

9. bindata.go: go generate生成的数据文件，包含conf.yml

## 5.2 子目录说明

1. conf: 实现DlpConf结构，处理配置文件。

2. detector: 敏感信息检测逻辑的内部实现。

3. errlist: 报错信息列表。

4. mask: 直接脱敏的内部实现。

5. util: 辅助功能实现。

6. dlpheader: dlp sdk 定义的接口头文件。

# 六、致谢

DLP项目从立项开始，一路走来，离不开其中辛苦付出的开发同学们，这里向为DLP写下代码的同学，致以最诚挚的感谢，以下同学排名不分先后。

- 丁保增 负责DLP1.0 识别信息验证模块。
- 王聪 负责DLP1.0 官网、JSON识别处理等模块、多个项目接入。
- 王赛 负责DLP1.0 去标识模块。
- 苏宁宁 负责DLP1.0 性能准确率测试。
- 王帅 负责DLP1.0 API头文件。
- 鲁云飞 负责DLP1.0 AI模块、NLP服务。
- 石岚 负责DLP1.0 AI模块，大数据处理API模块，发版等。
- 黄勇辉 负责DLP1.0 AI模块，优化更新了大量规则。
- 张宇鹏 参与DLP1.0 AI模块。
- 李赛南 参与DLP1.0 AI模块。
- 王珩 负责DLP1.0 保格式加密、保顺序加密模块。
- 夏世文 负责DLP1.0 性能优化、规则代码实现、主要完成了多个项目的合作开发工作。
- 罗同龙 为DLP2.0 提交了log处理性能优化的PR。
- 乔鑫 负责DLP2.0 服务端代码、SDK性能优化、技术实现。
- 杨经宇 负责DLP1.0 和 2.0的整体项目。
