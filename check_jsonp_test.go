package scripts

import (
	"fmt"
	"testing"
)

func Test_Check_Jsonp(t *testing.T) {
	//CheckJsRespAst()
	result, err := CheckSenseJsonp("http://127.0.0.1/jsonp_env/getUser.php?id=1&jsoncallback=callbackFunction")
	//result,err := CheckJsRespAst(`/**/callback_bilibili({"nick":"","code":0,"msg":"success","data":{"curPage":1,"pageCount":1,"totalSize":1,"pageSize":1,"data":[{"id":29749652,"title":"榛樿姝屽崟","type":1,"published":0,"cover":"","ctime":1566281377,"song":0,"desc":"","sids":[],"statistic":{"sid":29696064,"play":0,"collect":0,"comment":null,"share":0}}]}});`)
	fmt.Println(result)
	fmt.Println(err)
}
