# 基于AST的JSONP劫持漏洞检测(golang)



## **0x00 JSONP劫持简介**

- 敏感信息泄露引发的精准诈骗。
- 防守方的溯源能力之一，获取攻击者画像。

## **0x01 基于AST的JSONP劫持检测**

检测思路来源于xray核心开发者Koalr师傅  https://koalr.me/post/a-tour-of-xray/ 的分享。

本组件未单独提供爬虫，须结合爬虫使用。

## **0x02 核心逻辑**

1. 解析js路径，检查query所有key是否满足正则 (?m)(?i)(callback)|(jsonp)|(^cb$)|(function)

2. referer配置为同域，请求js获取响应

3. js响应生成AST，如果满足

   a) Callee.Name == callback函数名

   b) 递归遍历AST 获取所有的字段和对应的value

   c) 字段为敏感字段（满足正则(?m)(?i)(uid)|(userid)|(user_id)|(nin)|(name)|(username)|(nick)），且value不为空

4. 替换Referer后再请求一次，重新验证步骤3

## **0x03 调用方式**

提供了一个jsonp的漏洞环境，如需自取。

入参：js uri

返回：是否存在漏洞，err

例：

​	result, err := CheckSenseJsonp("http://127.0.0.1/jsonp_env/getUser.php?id=1&jsoncallback=callbackFunction")