# conf模块 实现说明

# conf文件结构

## 整体结构

config 文件以yaml格式为准，整体分为: `Global`,`MaskRules`,`Rules` 三个部分。其中：

1. Global

包含影响DLP全局的一些配置项，例如API版本、禁用的规则ID、是否启用后端服务辅助判断。

2. MaskRules

包含脱敏操作的配置，例如打码、替换等方式。

3. Rules

包含识别和处理规则，其中一个识别过程包括 Detect, Filter 和 Verify 三个依次的过程， 处理需要引用上面定义的脱敏规则。

## Global

Global配置项包含全局生效的配置，其中大部分通过名字可以理解其作用，剩下的配置项在这里说明:

- AllowRPC : 是否启用后端服务辅助判断结果，如果调用量巨大，期望高性能处理，就选择 false, 代表关闭后端服务辅助。
- DisableRules: 禁用的规则ID，一般用于修改系统默认规则，可以先禁用系统规则，然后根据原来的规则补充修改成一个自定义规则。

## MaskRules

MaskRules 配置项包含脱敏规则，是一个脱敏规则的列表，其中每个脱敏规则包含如下配置项：

- RuleName: 脱敏规则名称，用于Mask() API调用或者是被后面的识别处理规则所引用。
- MaskType: 脱敏类型，目前支持的类型有，[CHAR, TAG, REPLACE, ALGO ]。其中：

    CHAR: 用字符替换敏感信息，需要用到后面更详细的配置项。
    TAG: 用识别和处理规则中的InfoType, 以`<InfoType>`的形式替换敏感信息。
    REPLACE: 用Value定义的字符串，替换敏感信息，可以设定为空串，用于直接抹除。
    ALGO: 用Value定义的算法函数，处理敏感信息，用算法返回值替换原文，目前支持的算法有 [BASE64, MD5, CRC32]

- Value: 在不同脱敏类型中，传入不同的值
- Offset: 替换原文时，从Offset规定的偏移位置开始替换
- Length: 替换原文时，最多替换Length个byte的长度，0代表全替换
- Reverse: 是否从后往前替换
- IgnoreCharSet: 在 CHAR 脱敏类型中，如果遇到IgnoreCharSet字符串里面的CHAR，就不替换，例如邮箱就不替换`@`符号，忽略的符号不影响Length的计算
- IgnoreKind: 类似上面忽略符号，只是统一一些类型，支持的类型有 [NUMERIC 数字0-9, ALPHA_UPPER_CASE 大写字母, ALPHA_LOWER_CASE 小写字母, WHITESPACE 空白符, PUNCTUATION 标点符号] ， 具体定义见实现代码

## 默认conf文件

`conf.yml` 这个文件是DLP内置的默认conf文件。






