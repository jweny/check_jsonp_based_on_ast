<?php
header('Content-type: application/json');
$jsoncallback = htmlspecialchars($_REQUEST ['jsoncallback']);//获取回调函数名
//json数据
//$json_data = '["id","user"]';
$json_data='({"hh":"1","name":"fsdfa"})';
echo $jsoncallback . "(" . $json_data . ")";//输出jsonp格式的数据
?>