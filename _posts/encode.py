
文件读取
PHP normalizes / and /. in path names allowing for example /etc/passwd/ or /etc/passwd/. to be succesfully opened as a file.
window截断
file.est./././[OMIT]./.php" will work, while the already seen "file.est/././[OMIT]././.php" will not
.\一样也能工作

file=poc_blacklist_bypass_read.php black
file=poc_blacklist_bypass_read.php/. bypass


file:///
<?php 
$gfile = $_GET['gfile'];
if (isset($gfile)){
    print_r(file_get_contents($gfile));
}else {
    print_r("Please input gfile !<br />");
}
// ?gfile=file://C:\mySoft\xampp\htdocs\phpinfo.php
// ?gfile=file://C:/mySoft/xampp/htdocs/phpinfo.php

file:///
<?php 
$gfile = $_GET['gfile'];
if (isset($gfile)){
    print_r(file_get_contents($gfile));
}else {
    print_r("Please input gfile !<br />");
}
// ?gfile=file://C:\mySoft\xampp\htdocs\phpinfo.php
// ?gfile=file://C:/mySoft/xampp/htdocs/phpinfo.php


All of the following paths are valid and equivalent when given to the Windows shell:	
– file.txt
– file.txt.....
– file.txt<spaces>
– file.txt””””
– file t t<<<>><>< file.t
xt<<<>><><
– file.txt/././././.
– nonexistant/../file.txt
• Different technique, similar use
– “highlight.php” != “highlight.php.”
–
“restricted txt restricted.txt
” !=
“restricted txt<space> restricted.txt<space>
”


 So you would need file:///home/User/2ndFile.html (on most Unixes), file:///Users/User/2ndFile.html (on Mac OS X), or file:///C:/Users/User/2ndFile.html (on Windows).

登陆认证模块
验证码不重置
本地加密传输设置	#wireshark查看密码 待测试
session会话固定测试
session会话注销测试
session会话超时测试
cookie串改userid=admin
密码比对认证测试	前端hash加密如pwd=1d3sdsdsfjgfjgfkhkfgh
登陆失败信息测试

业务办理模块测试
任意订单遍历 id=
手机号码	#最后一步更改手机号挂失他人手机
任意用户id修改 遍历用户身份信息
邮件篡改测试	#篡改发件人参数 伪造发信人 发送钓鱼邮件
篡改商品id编号		#修改商品id以低价购买


__VIEWSTATE=11	#查看aspx报错信息	client ip可能是目标服务器或是你自己的



WM_SHOP_LOGIN_COOKIE=NTA2MTEzNTkyOjMxNTI2MzM4MmNhMWE2MTU2NTU0OGYzZWJiMWY3NWEx;
WM_SHOP_LOGIN_COOKIE=NTA2MTEzNTkyOjMxNTI2MzM4MmNhMWE2MTU2NTU0OGYzZWJiMWY3NWEx;


对域名进行解析，检查解析的ip不是内网ip即可。	漏洞304



