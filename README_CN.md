本 Wiki 旨在提供一个建立灵活 Red Team 基础设施的资源。为了补充 Steve Borosh ([@424f424f](https://twitter.com/424f424f)) 和 Jeff Dimmock ([@bluscreenofjeff](https://twitter.com/bluscreenofjeff)) 在 BSides NoVa 2017 上的演讲 "Doomsday Preppers: Fortifying Your Red Team Infrastructure" 您可以查看([幻灯片](https://speakerdeck.com/rvrsh3ll/doomsday-preppers-fortifying-your-red-team-infrastructure))

如果您有需要添加的内容，请提交 PR 或者在 issue 中提出问题。

感谢本 Wiki 中提到的所有工具的作者和所有的贡献者！

# 目录

- [设计注意事项](#设计注意事项)
  - [功能分离](#功能分离)
  - [使用重定向器](#使用重定向器)
  - [示例设计](#示例设计)
  - [更多资源](#更多资源)
- [域名](#域名)
  - [分类与黑名单检查](#分类与黑名单检查)
- [钓鱼部署](#钓鱼部署)
  - [简单基于 Web 的钓鱼](#简单基于-Web-的钓鱼)
  - [Cobalt Strike 钓鱼](#Cobalt-Strike-钓鱼)
  - [钓鱼框架](#钓鱼框架)
- [重定向器](#重定向器)
  - [SMTP](#smtp)
    - [发送邮件](#发送邮件)
      - [移除先前服务器 Header](#移除先前服务器-Header)
      - [配置一个通用地址](#配置一个通用地址)
    - [后缀](#后缀)
  - [DNS](#dns)
    - [socat for DNS](#socat-for-dns)
    - [iptables for DNS](#iptables-for-dns)
  - [HTTP(S)](#https)
    - [socat vs mod_rewrite](#socat-vs-mod_rewrite)
    - [socat for HTTP](#socat-for-http)
    - [iptables for HTTP](#iptables-for-http)
    - [Payloads and Web Redirection](#payloads-and-web-redirection)
    - [C2 Redirection](#c2-redirection)
      - [C2 Redirection with HTTPS](#c2-redirection-with-https)
    - [Other Apache mod_rewrite Resources](#other-apache-mod_rewrite-resources)
- [Modifying C2 Traffic](#modifying-c2-traffic)
  - [Cobalt Strike](#cobalt-strike)
  - [Empire](#empire)
- [第三方 C2 信道](#第三方-C2-信道)
  - [Domain Fronting](#domain-fronting)
    - [关于 Domain Fronting 的更多资源](#关于Domain-Fronting的更多资源)
  - [PaaS 重定向器](#PaaS重定向器)
  - [其他第三方C2](#其他第三方C2)
- [隐藏基础设施](#obscuring-infrastructure)
- [保证基础设施的安全](#securing-infrastructure)
- [自动化部署](#automating-deployments)
- [一般技巧](#一般技巧)
- [感谢贡献者](#感谢贡献者)

# 设计注意事项

## 功能分离
设计一个经得起积极响应和长期维持（数周、数月、数年）的 Red Team 基础架构时，根据功能分离每项资产非常重要。活动资产被检测到时，为 Blue Team 提供弹性和灵活性。例如，如果钓鱼邮件被识别出来，Red Team 只需要创建一个新的 SMTP 服务器和一个 Payload 托管服务器，而不是全部基础设施

考虑在不同的资产上分离这些功能：
* 钓鱼 SMTP 服务器
* 钓鱼 Payloads
* 长期 C2
* 短期 C2

每个社会工程活动可能都需要这些功能，由于主动应急响应在 Red Team 的评估中是常见的，所以应为每个活动部署一套新的基础设施

## 使用重定向器
为了进一步提高弹性和隐蔽性，每个后端资产（团队服务器）都应该在前面放置一个重定向器。我们的目标是在目标和后端服务器之间维持一个主机，以这种方式配置基础架构可以更轻松地完成任务，无需新的团队服务器、迁移会话并重新连接后端的未记录资产

常见的重定向器类型：
* SMTP
* Payloads
* Web Traffic
* C2 (HTTP(S), DNS, etc)

每个类型的重定向器都有多个最适合不同的最佳场景。这些选项将在 [重定向器](#redirectors) 部分进一步讨论。重定向器可以是 VPS 主机、专用服务器，甚至是在 PaaS 的实例上运行的应用程序

## 示例设计
以下是一个示例设计，保持功能隔离与重定向：

![Sample Infrastructure Setup](./images/sample-setup.png)

## 更多资源

* [分布式 Red Team 运作 - Raphael Mudge (@armitagehacker)](https://blog.cobaltstrike.com/2013/02/12/a-vision-for-distributed-red-team-operations/)

* [Red Team 运作基础设施 - Raphael Mudge](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations/)

* [高级威胁战术 (2 of 9): 基础设施 - Raphael Mudge](https://www.youtube.com/watch?v=3gBJOJb8Oi0)

* [用于分布式环境、基于云的重定向器 - Raphael Mudge](https://blog.cobaltstrike.com/2014/01/14/cloud-based-redirectors-for-distributed-hacking/)

* [6 个 Red Team 基础设施技巧 - Alex Rymdeko-Harvey (@killswitch-gui)](https://cybersyndicates.com/2016/11/top-red-team-tips/)

* [如何使用 Digital Ocean 构建 C2 基础设施 – Part 1 - Lee Kagan (@invokethreatguy)](https://www.blackhillsinfosec.com/build-c2-infrastructure-digital-ocean-part-1/)

* [使用 Terraform 自动部署 Red Team 基础设施 - Part 1 - Rasta Mouse (@_RastaMouse)](https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform---part-1/)

# 域名
域名信誉依据所使用的产品和配置有很大差异。因此，选择一个适用于您情况的域名并不是一门科学。OSINT 对帮助最好地猜测控制状态、检查域名所针对的资源至关重要。幸运的是，在线广告商同样面临相同的问题，已经创造了一些我们可以利用的解决方案

[expireddomains.net](http://expireddomains.net) 是最近过期或已删除的域名搜索引擎。它提供搜索和高级过滤功能，例如按照到期时间、反链数量、Archive.org 快照数、[SimilarWeb](https://www.similarweb.com/) 分数等。使用该网站，我们可以抢先注册想要使用的域名，这些域名将和他们的“年龄”一同显示，我们想要找那些和目标类似的，或者看起来类似的，或者仅仅能融入我们的目标网络的

![expireddomains.net](./images/expired-domains.png)

在为 C2 或数据泄露选择域名时，考虑选择一个分类为财务或医疗保健的域名。由于法律或数据敏感性的问题，许多组织不会在这些类别中执行 SSL 等规定

Charles Hamilton([@MrUn1k0d3r](https://twitter.com/mrun1k0d3r)) 的工具 [CatMyFish](https://github.com/Mr-Un1k0d3r/CatMyFish) 使用 expireddomains.net 和 BlueCoat 自动执行搜索与 Web 分类检查。可对其进行修改，以便支持更多的过滤器，甚至对您注册的资产进行长期监控

Joe Vest ([@joevest](https://twitter.com/joevest)) 和 Andrew Chiles ([@andrewchiles](https://twitter.com/andrewchiles)) 的另一个工具 [DomainHunter](https://github.com/minisllc/domainhunter) 基于 CatMyFish，返回 BlueCoat 和 IBM X-Force 分类、域名“年龄”、替换可用 TLD、Archive.org 链接和 HTML 报告。可以详细查看 [博客](http://threatexpress.com/2017/03/leveraging-expired-domains-for-red-team-engagements/)

[Max Harley (@Max_68)](https://twitter.com/@Max_68) 的工具 [AIRMASTER](https://github.com/t94j0/AIRMASTER) 使用 expireddomains.net 和 Bluecoat 来找到分类的域名，该工具使用 OCR 绕过 Bluecoat 的验证码以提高搜索速度

如果以前注册的域名不可用，或者您更愿意使用自己注册的域名，可以自行对域名进行分类。使用下面的链接或 Dominic Chell ([@domchell](https://twitter.com/domchell)) 的 [Chameleon](https://github.com/mdsecactivebreach/Chameleon)。确定域名分类时，大多数分类产品都会忽略重定向或克隆。有关 Chameleon 的更多信息，请查看 Dominic 的博客 [Categorisation is not a security boundary](https://www.mdsec.co.uk/2017/07/categorisation-is-not-a-security-boundary/)

最后，确保您的 DNS 设置可以正确生效
* [DNS Propogation Checker](https://dnschecker.org/)

## 分类与黑名单检查
* [McAfee](https://trustedsource.org/en/feedback/url?action=checksingle)
* [Fortiguard](http://www.fortiguard.com/iprep)
* [Symantec + BlueCoat](http://sitereview.bluecoat.com/sitereview.jsp)
* [Checkpoint (requires free account)](https://www.checkpoint.com/urlcat/main.htm)
* [Palo Alto](https://urlfiltering.paloaltonetworks.com/)
* [Sophos (submission only; no checking)](https://secure2.sophos.com/en-us/support/contact-support.aspx) - Click Submit a Sample -> Web Address
* [TrendMicro](https://global.sitesafety.trendmicro.com/)
* [Brightcloud](http://www.brightcloud.com/tools/url-ip-lookup.php)
* [Websense (Forcepoint)](http://csi.websense.com/)
* [Lightspeed Systems](https://archive.lightspeedsystems.com/)
* [Chameleon](https://github.com/mdsecactivebreach/Chameleon)
* [SenderBase](https://www.senderbase.org/)
* [MultiBL](http://multirbl.valli.org/)
* [MXToolBox - Blacklists](https://mxtoolbox.com/blacklists.aspx)

# 钓鱼部署

## 简单基于 Web 的钓鱼
简单和钓鱼似乎不应该同时出现，建立一个合适的网络钓鱼基础设施很可能非常艰难。本节将提供如何快速设置一个钓鱼服务器的相关知识和工具，该服务器可以通过“大多数”垃圾邮件过滤器，并提供一个简单的钓鱼体验，包括与您的目标进行双向通信的 RoundCube 界面。网络钓鱼方面有很多相关内容，这只是一种方法

一旦您的域名通过了上述检查，在您的钓鱼服务器启动后，您需要按照下图所示，为域名创建一对 A 记录

![DNS Setup](./images/setup_dns_a_record_for_ssl.PNG)

接下来，要进入钓鱼服务器并下载以下脚本来对基础设施进行配置：[Postfix-Server-Setup-Script](https://github.com/n0pe-sled/Postfix-Server-Setup)

将脚本设置为可执行，例如 `chmod +x ServerSetup.sh`。现在运行安装脚本，方法是在多个选项中选择一个适合自己的，脚本会安装适当的依赖并设置 hostname

![Setup Script](./images/setup_script.PNG)

服务器将会重新启动，SSH 连接服务器再次运行脚本。这一次选择 4 来安装 LetsEncrypt 证书。确保你的 A 记录已经设置并生效。按照提示进行操作，如果成功创建证书，将会看到以下消息：

![Cert Creation](./images/cert-creation.PNG)

接下来，选择 5 来设置邮件服务器。再次按照提示进行操作，将引导您设置一个可以正常工作的邮件服务器。之后，按照 7 得到添加到 DNS 记录中的 DNS 条目。提示，脚本输出这些条目在 dnsentries.txt 中

前部分就完成了，接下来通过几个简单的步骤来完善钓鱼流程。首先将最新版本的 [iRedMail](http://www.iredmail.org/download.html) 下载到钓鱼服务器上。简单的办法是右键点击下载按钮，复制链接地址，使用 wget 下载到钓鱼服务器上。解压缩可能需要 bzip2 程序，解压后在文件夹中为 iRedMail.sh 脚本赋予执行权限 (chmod +x iRedMail.sh)。以 root 的权限执行脚本，按照提示进行操作，并登录到 iRedMail 服务器的管理页面

![iRedMail 管理页面](./images/iredadmin_dashboard.PNG)

现在，创建一个新用户

![iRedMail 创建用户](./images/iredadmin_user_add.PNG)

登录到 RoundCube 的界面

![RoundCube 登录](./images/roundcube_login.PNG)

![RoundCube 发送邮件](./images/final_phish_away.PNG)

## Cobalt Strike 钓鱼
Cobalt Strike 提供定制化的钓鱼功能，以支持渗透测试人员或 Red Team 通过电子邮件进行钓鱼。它支持 HTML 或纯文本格式的模版、附件、反弹地址、URL 嵌入、远程 SMTP 服务器以及每个消息的发送延迟的定制。另一个有趣的功能是能够为每个用户嵌入的 URL 添加唯一标记以进行点击跟踪

![Cobalt Strike Spearphishing Popup](/images/cobalt-strike-phishing-popup.png)

想了解更多信息，请看以下资源：

* [Cobalt Strike - 鱼叉式钓鱼文档](https://www.cobaltstrike.com/help-spear-phish)
* [Cobalt Strike Blog - 什么是钓鱼？](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
* [使用 Cobalt Strike 完成钓鱼- Raphael Mudge](https://www.youtube.com/watch?v=V7UJjVcq2Ao)
* [高级威胁战术 (3 of 9) - 针对性攻击 - Raphael Mudge](https://www.youtube.com/watch?v=CxQfWtqpwRs)


## 钓鱼框架
除了自己开发的、团队协作框架提供的钓鱼功能外，还有很多专门用于网络钓鱼的工具和框架。尽管我们不会详细介绍每个框架，但每个框架都收集了一些相关资源：

### Gophish
* [Gophish 官方网站](https://getgophish.com/)
* [Gophish GitHub 仓库](https://github.com/gophish/gophish)
* [Gophish 用户指南](https://www.gitbook.com/book/gophish/user-guide/details)

### Phishing Frenzy

* [Phishing Frenzy 官方网站](https://www.phishingfrenzy.com/)
* [Phishing Frenzy GitHub 仓库](https://github.com/pentestgeek/phishing-frenzy)
* [介绍 Phishing Frenzy - Brandon McCann (@zeknox)](https://www.pentestgeek.com/phishing/introducing-phishing-frenzy)

### 社会工程工具集
* [社会工程工具集 GitHub 仓库](https://github.com/trustedsec/social-engineer-toolkit)
* [社会工程工具集使用者手册](https://github.com/trustedsec/social-engineer-toolkit/raw/master/readme/User_Manual.pdf)

### FiercePhish (原 FirePhish)
* [FiercePhish GitHub 仓库](https://github.com/Raikia/FiercePhish)
* [FiercePhish Wiki](https://github.com/Raikia/FiercePhish/wiki)

# 重定向器

## SMTP
“重定向器”也许不是描绘我们想法的最佳词汇，但目标是类似的。我们希望从最终的电子邮件 Header 中删掉我们钓鱼邮件的痕迹，并在受害者和我们的后端服务器间提供缓冲区。理想情况下，SMTP 重定向器便于部署与停用。

我们想要配置 SMTP 重定向器来执行两个关键操作：

### 发送邮件

#### 移除先前服务器 Header
将以下内容添加到 `/etc/mail/sendmail.mc` 的末尾：

```bash
define(`confRECEIVED_HEADER',`by $j ($v/$Z)$?r with $r$. id $i; $b')dnl
```

将以下内容添加到 `/etc/mail/access` 的末尾：

```bash
IP-to-Team-Server *TAB* RELAY
Phish-Domain *TAB* RELAY
```

[在收件人的邮件中删除发件人的 IP 地址](https://www.devside.net/wamp-server/removing-senders-ip-address-from-emails-received-from-header)

[在 Postfix 设置中删除 Headers](https://major.io/2013/04/14/remove-sensitive-information-from-email-headers-with-postfix/)

#### 配置一个通用地址
将收到的电子邮件转发到 *@phishdomain.com，这对接收响应或电子邮件的反射非常有用。

```bash
echo PHISH-DOMAIN >> /etc/mail/local-host-names
```

在 `/etc/mail/sendmail.mc` 结尾的 `//Mailer Definitions//` 前加入如下内容

```bash
FEATURE(`virtusertable', `hash -o /etc/mail/virtusertable.db')dnl
```

在 `/etc/mail/virtusertable` 的结尾处加入如下内容：

```bash
@phishdomain.com  external-relay-address
```

*提示：这两个字段应该用 tab 分割*

### 后缀

后缀提供了更好的兼容性，后缀还为 Dovecot 提供全面的 IMAP 支持。这使得测试人员能够实时地将原始消息和作出响应的目标相对应，而不是完全依靠捕获地址，而且可以使用钓鱼工具创建新消息

Julian Catrambone ([@n0pe_sled](https://twitter.com/n0pe_sled)) 发布的博客 [Mail Servers Made Easy](https://blog.inspired-sec.com/archive/2017/02/14/Mail-Server-Setup.html)解释了一个用于设置网络钓鱼后缀邮件服务器的完整指南

## DNS

![Sample DNS Redirector Setup](./images/dns_redirection.png)

注意：使用 C2 重定向时，应该在投递利用框架中配置外部监听器，以通过重定向域名分段传输。这会让受感染的主机像 C2 流量本身一样通过重定向器

### socat for DNS
socat 将 53 端口传入的 DNS 数据包重定向到我们的团队服务器，尽管此方法是有效的，但某些用户也报告了一些问题

感谢 @xorrior 的测试：
```
socat udp4-recvfrom:53,reuseaddr,fork udp4-sendto:<IPADDRESS>; echo -ne
```

[重定向 Cobalt Strike 的 DNS 流量 - Steve Borosh](http://www.rvrsh3ll.net/blog/offensive/redirecting-cobalt-strike-dns-beacons/)


### iptables for DNS
iptables 配置 DNS 转发规则可与 Cobalt Strike 配合使用。socat 处理这种类型的流量时似乎没遇到过什么问题

一个 DNS 重定向规则集示例：

```bash
iptables -I INPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination <IP-GOES-HERE>:53
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -I FORWARD -j ACCEPT
iptables -P FORWARD ACCEPT
sysctl net.ipv4.ip_forward=1
```

将 “FORWARD” 链策略改为 “ACCEPT”

### DNS redirection can also be done behind NAT
可能需要在内部网络中部署 C2 服务器，使用 iptables、socat 和反向 SSH 隧道的组合，通过以下方式来实现：

![Sample DNS NAT Setup](./images/dns_nat.png)

在这种情况下，我们利用 iptables 使用本节前面介绍的规则示例转发所有 DNS 流量。接下来，我们创建一个从我们内部 C2 服务器到我们的主重定向器的 SSH 反向端口转发隧道。这会将主重定向器在端口 6667 上接收的全部流量转发到内部 C2 服务器的端口 6667 上。现在，启动我们的团队服务器上的 socat，将 6667 端口上的任何传入 TCP 流量分流到 UDP 端口 53。最后，我们在主重定向器上同样设置一个 socat 实例，将任何传入的 UDP 端口 53 流量重定向到端口 6667 上的 SSH 隧道


## HTTP(S)

注意：使用 C2 重定向时，应该在投递利用框架中配置外部监听器，以通过重定向域名分段传输。这会让受感染的主机像 C2 流量本身一样通过重定向器

### socat vs mod_rewrite
socat 提供 `dumb pipe` 重定向，在指定的源端口上接收到的任何请求都会被重定向到目标端口。没有任何过滤或条件的重定向。另一方面，Apache 的 `mod_rewrite` 提供了许多方法来增强钓鱼并且增加基础架构的弹性。`mod_rewrite` 能够根据请求数据执行条件重定向（如 URI、User-Agent、Query String、OS、IP）。其使用 htaccess 文件来对 Apache 处理每个传入请求的规则集进行配置。例如，使用这些规则可以根据 wget 默认的 User-Agent 将其请求重定向到您的服务器，以将其转移到目标网站上的合法页面

简而言之，如果您的重定向器需要执行条件重定向或高级过滤，请使用 Apache mod_rewrite，否则，使用 iptables 进行过滤，配合 socat 的重定向就足够了

### socat for HTTP
socat 可用于将指定端口上任意传入的 TCP 数据包重定向到我们的团队服务器

将 localhost 的 80 端口重定向到另一台主机上的 80 端口的语法是：

```
socat TCP4-LISTEN:80,fork TCP4:<REMOTE-HOST-IP-ADDRESS>:80
```

如果您配置了多个网络接口，也可以使用如下语法将 socat 绑定到特定的端口/地址上：

```
socat TCP4-LISTEN:80,bind=10.0.0.2,fork TCP4:1.2.3.4:80
```
本例中，10.0.0.2 是一个重定向器的本地 IP 地址，1.2.3.4 是远程团队服务器的 IP 地址

### iptables for HTTP
除了 socat 和 iptables 可以通过 NAT 执行 dumb pipe 重定向。要将重定向器的本地 80 端口转发到远程主机，请使用以下如法：

```
iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination <REMOTE-HOST-IP-ADDRESS>:80
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -I FORWARD -j ACCEPT
iptables -P FORWARD ACCEPT
sysctl net.ipv4.ip_forward=1
```

### Payloads and Web Redirection
无论在建立 C2 还是收集情报阶段，当提供 payload 和 Web 资源时，我们想要最小化应急响应者检查文件的能力，并增加成功执行 payload 的可能性

![Sample Apache Redirector Setup](./images/apache-redirector-setup.png)

Jeff Dimmock 提供的 Apache Mod_Rewrite 用法与示例：
* [Strengthen Your Phishing with Apache mod_rewrite](https://bluescreenofjeff.com/2016-03-22-strengthen-your-phishing-with-apache-mod_rewrite-and-mobile-user-redirection/)
* [Invalid URI Redirection with Apache mod_rewrite](https://bluescreenofjeff.com/2016-03-29-invalid-uri-redirection-with-apache-mod_rewrite/)
* [Operating System Based Redirection with Apache mod_rewrite](https://bluescreenofjeff.com/2016-04-05-operating-system-based-redirection-with-apache-mod_rewrite/)
* [Combatting Incident Responders with Apache mod_rewrite](https://bluescreenofjeff.com/2016-04-12-combatting-incident-responders-with-apache-mod_rewrite/)
* [Expire Phishing Links with Apache RewriteMap](https://bluescreenofjeff.com/2016-04-19-expire-phishing-links-with-apache-rewritemap/)
* [Apache mod_rewrite Grab Bag](https://bluescreenofjeff.com/2016-12-23-apache_mod_rewrite_grab_bag/)
* [Serving Random Payloads with Apache mod_rewrite](https://bluescreenofjeff.com/2017-06-13-serving-random-payloads-with-apache-mod_rewrite/)

其他 Apache mod_rewrite 用法与示例：

* [mod_rewrite rule to evade vendor sandboxes from Jason Lang @curi0usjack](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10) 

* [Serving random payloads with NGINX - Gist by jivoi](https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9)

为了在重定向服务器上自动设置 Apache Mod_Rewrite，请查看 Julain Catrambone's ([@n0pe_sled](https://twitter.com/n0pe_sled)) 的博客 [Mod_Rewrite Automatic Setup](https://blog.inspired-sec.com/archive/2017/04/17/Mod-Rewrite-Automatic-Setup.html) 与 [accompanying tool](https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup).

### C2 Redirection
重定向 C2 流量有两方面的意义：隐藏后端团队服务器，并且在应急响应调查浏览时显示为合法网站。通过使用 Apache mod_rewrite 和 [自定义 C2 配置文件customized C2 profiles](#modifying-c2-traffic)或者其他代理（如 Flask），我们可以可靠地过滤真实的 C2 流量

* [Cobalt Strike HTTP C2 Redirectors with Apache mod_rewrite - Jeff Dimmock](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/)
* [Securing your Empire C2 with Apache mod_rewrite - Gabriel Mathenge (@_theVIVI)](https://thevivi.net/2017/11/03/securing-your-empire-c2-with-apache-mod_rewrite/)
* [Expand Your Horizon Red Team – Modern SAAS C2 - Alex Rymdeko-Harvey (@killswitch-gui)](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/)

#### C2 Redirection with HTTPS
重定向服务器可以十一on个 Apache 的 SSL 代理引擎来接受入站 SSL 请求，并将这些请求代理到反向 HTTPS 监听器。为了将加密应用于所有阶段，可以根据需要在重定向服务器上轮换 SSL 证书

为了使 mod_rewrite 规则能够工作，需要将规则放在 **"/etc/apache2/sites-available/000-default-le-ssl.conf"** 中，假设你已经使用了 LetsEncrypt 来安装证书，还需要启动 SSL ProxyPass 引擎，需要在同一个配置文件中增加如下内容：

```bash
# 启动代理引擎
SSLProxyEngine On

# 通知代理引擎请求如何转发
ProxyPass / https://DESTINATION_C2_URL:443/
ProxyPassReverse / https://DESTINATION_C2_URL:443/

# 禁用证书检查，如果使用的是自签名证书会非常有用
SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
```

### 其他 Apache mod_rewrite 资源
* [mod-rewrite-cheatsheet.com](http://mod-rewrite-cheatsheet.com/)
* [Official Apache 2.4 mod_rewrite Documentation](http://httpd.apache.org/docs/current/rewrite/)
* [Apache mod_rewrite Introduction](https://httpd.apache.org/docs/2.4/en/rewrite/intro.html)
* [An In-Depth Guide to mod_rewrite for Apache](http://code.tutsplus.com/tutorials/an-in-depth-guide-to-mod_rewrite-for-apache--net-6708)
* [Mod_Rewrite/.htaccess Syntax Checker](http://www.htaccesscheck.com/)

# Modifying C2 Traffic

## Cobalt Strike
Cobalt Strike 通过 Malleable C2 文件来修改流量，配置文件提供了高度定制的选项。用于修改线路中服务器 C2 流量的特征，可扩展的 C2 配置文件可用于加强事件响应规避，冒充已知的、目标使用的合法内部应用程序。

* [Malleable C2 Profiles - GitHub](https://github.com/rsmudge/Malleable-C2-Profiles)
* [Malleable Command and Control Documentation - cobaltstrike.com](https://www.cobaltstrike.com/help-malleable-c2)
* [Cobalt Strike 2.0 - Malleable Command and Control - Raphael Mudge](http://blog.cobaltstrike.com/2014/07/16/malleable-command-and-control/)
* [Cobalt Strike 3.6 - A Path for Privilege Escalation - Raphael Mudge](http://blog.cobaltstrike.com/2016/12/08/cobalt-strike-3-6-a-path-for-privilege-escalation/)
* [A Brave New World: Malleable C2 - Will Schroeder (@harmj0y)](http://www.harmj0y.net/blog/redteaming/a-brave-new-world-malleable-c2/)
* [How to Write Malleable C2 Profiles for Cobalt Strike - Jeff Dimmock](https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/)


## Empire
Empire 使用通信配置文件来提供定制 URI、User-Agent、Header 的 GET 请求。该配置文件由管道分隔符隔开的元素组成，并配置 `listeners` 上下文菜单中的 `set DefaultProfile` 选项。

这是一些默认配置文件：

```bash
"/CWoNaJLBo/VTNeWw11212/|Mozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.1)|Accept:image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*|Accept-Language:en-en"
```

或者，可以通过 `/setup/setup_database.py` 在 Empire 设置之前修改文件来设置 DefaultProfile 的值

除通信配置文件外，请考虑按照 Joe Vest([@joevest](https://twitter.com/joevest))发布的文章，[Empire - 修改服务器 C2 指标](http://threatexpress.com/2017/05/empire-modifying-server-c2-indicators/) 介绍的步骤来定制 Empire 的登录 URI、Headers 和默认的网页内容

* [默认 Empire 通信配置文件（Empire 的 GitHub 仓库）](https://github.com/EmpireProject/Empire/tree/master/data/profiles)
* [如何为 Empire 配置通信配置文件 - Jeff Dimmock](https://bluescreenofjeff.com/2017-03-01-how-to-make-communication-profiles-for-empire/)

# 第三方 C2 信道
利用可信的、合法的 Web 服务器进行 C2 可以提供配置您自己的域名和基础架构的帮助。配置时间和复杂程度取决于使用的技术和服务，利用第三方服务进行 C2 重定向的一个流行示例是 Domain Fronting

## Domain Fronting
Domain Fronting 是一种用于规避服务和应用程序检查的技术，通过合法和高度可信的域进行流量传输的技术。支持 Domain Fronting 的服务包括 [Google App Engine](https://cloud.google.com/appengine/)、[Amazon CloudFront](https://aws.amazon.com/cloudfront/) 和 [Microsoft Azure](https://azure.microsoft.com/)。简而言之，流量使用受信任的服务提供商的 DNS 和 SNI name。当边缘服务器接收到流量时（例如，gmail.com），数据包将被转发到数据包的主机头中指定的原始服务器（例如，phish.appspot.com）。根据服务提供商的不同，原始服务器会直接将流量转发到指定的域名，指向我们的团队服务器，或者通过代理来进行最后一跳转发

![Domain Fronting Overview](./images/domain-fronting.png)
有关 Domain Fronting 如何工作的更多详细信息，请参阅白皮书：通过域前端进行阻止阻止通信以及TOR Project的温文档
For more detailed information about how Domain Fronting works, see the whitepaper [通过 Domain Fronting 绕过通信限制](https://www.bamsoftware.com/papers/fronting/) 和 Tor 团队的 [meek documentation](https://trac.torproject.org/projects/tor/wiki/doc/meek)

除了标准可 Fronting 的域名之外，还可以利用其他合法域名作为前端

有关狩猎可 Fronting 的域名，可以查看：
* [通过 Cloudfront Alternate Domains 实现 Domain Fronting - Vincenty Yiu (@vysecurity)](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)
* [发现 Azure 中 Fronting 的域名 - thoth / Fionnbharr (@a_profligate)](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)
* [使用 Censys 查找两千个以上 Azure 域名](https://groups.google.com/forum/#!topic/traffic-obf/7ygIXCPebwQ)
* [查找可 Fronting 的域名的工具 - Steve Borosh (@rvrsh3ll)](https://github.com/rvrsh3ll/FindFrontableDomains)

### 关于Domain Fronting的更多资源
* [Simplifying Domain Fronting - Tim Malcomvetter (@malcomvetter)](https://medium.com/@malcomvetter/simplifying-domain-fronting-8d23dcb694a0)
* [High-reputation Redirectors and Domain Fronting - Raphael Mudge](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
* [Empire Domain Fronting - Chris Ross (@xorrior)](https://www.xorrior.com/Empire-Domain-Fronting/)
* [Escape and Evasion Egressing Restricted Networks - Tom Steele (@_tomsteele) and Chris Patten](https://www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks)
* [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/) - [Will Vandevanter and Shay Nahari of CyberArk](https://www.cyberark.com)
* [SSL Domain Fronting 101 - Steve Borosh (@424f424f)](http://www.rvrsh3ll.net/blog/offensive/ssl-domain-fronting-101/)

## PaaS重定向器
许多 PaaS 和 SaaS 服务商提供了一个静态子域或 URL 供实例使用。如果关联域名是高度可信的，则这些实例可以通过购买的域名和 VPS 为您的 C2 基础架构提供额外的信任

要设置重定向，您需要确定可以将静态子域名或 URL 作为实例的一部分发布的那些服务。然后，实例将需要使用网络或基于应用程序的重定向进行配置。该实例将充当代理，与此 wiki 上讨论的其他重定向器类似

根据服务的具体情况，实施可能会有很大差异; 然而，对于使用 Heroku 的一个例子，[Alex Rymdeko-Harvey (@Killswitch_GUI)](https://twitter.com/Killswitch_GUI) 写的博客[Expand Your Horizon Red Team – Modern SaaS C2](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/) 

另一个值得进一步研究的技术是使用宽松的 Amazon S3buckets 用于 C2。查看 [Andrew Luke (@Sw4mp_f0x)](https://twitter.com/Sw4mp_f0x) 发布的[S3 Buckets for Good and Evil](https://pentestarmoury.com/2017/07/19/s3-buckets-for-good-and-evil/)，可以了解更多关于 S3 如何用于 C2 的细节。这种技术可以与 Empire 的第三方 C2 能力结合使用

## 其他第三方C2
过去，其他第三方服务已经在野外被广泛应用于 C2。利用允许用户生成内容的第三方网站可以帮助您逃避基于声誉的检查，尤其是在第三方网站普遍受到信任的情况下

查看其他第三方 C2 可选择的资源：
* [使用 GitHub 作为基于 Python 的隐藏式 Windows后门程序的 C&C 服务器](http://securityblog.gr/4434/a-stealthy-python-based-windows-backdoor-that-uses-github-as-a-cc-server/) - [maldevel at securityblog.gr](http://securityblog.gr/author/gkarpouzas/)
* [外部 C2 （第三方 C&C） - Cobalt Strike 文档](https://www.cobaltstrike.com/help-externalc2)
* [通过外部 C2 使用 Cobalt Strike](https://outflank.nl/blog/2017/09/17/blogpost-cobalt-strike-over-external-c2-beacon-home-in-the-most-obscure-ways/) - [Mark Bergman at outflank.nl](https://outflank.nl/blog/author/mark/)
* [“Tasking” Office 365 用于 Cobalt Strike C2](https://labs.mwrinfosecurity.com/blog/tasking-office-365-for-cobalt-strike-c2) - [William Knowles (@william_knows)](https://twitter.com/william_knows)
* [Cobalt Strike 可用的外部 C2](https://github.com/ryhanson/ExternalC2/) - [Ryan Hanson (@ryhanson)](https://twitter.com/ryhanson)
* [Cobalt Strike 的外部 C2 框架](http://www.insomniacsecurity.com/2018/01/11/externalc2.html) - [Jonathan Echavarria (@Und3rf10w)](https://twitter.com/und3rf10w)
* [外部 C2 框架（GitHub 仓库）](https://github.com/Und3rf10w/external_c2_framework) - [Jonathan Echavarria (@Und3rf10w)](https://twitter.com/und3rf10w)

# 隐藏基础设施
攻击基础设施通常容易识别，我们需要将其伪装为合法的服务器。我们需要采取额外的措施来增加我们的基础设施和真实服务器混合的可能性，这些服务器不在目标组织中，就在目标可能使用的服务中。

[重定向工具](#redirectors) 可以通过 [重定向无效 RI](https://bluescreenofjeff.com/2016-03-29-invalid-uri-redirection-with-apache-mod_rewrite/)、[过滤钓鱼 payload 链接](https://bluescreenofjeff.com/2016-04-19-expire-phishing-links-with-apache-rewritemap/) 或 [阻止常见事件响应技术](https://bluescreenofjeff.com/2016-04-12-combatting-incident-responders-with-apache-mod_rewrite/) 来帮助混合，但是还要注意潜在的主机及其指标信息

例如，在 [Empire 投递](http://securesql.info/hacks/2017/4/5/fall-of-an-empire) 后，John Menerick ([@Lord_SQL](https://twitter.com/Lord_SQL)) 介绍了在互联网中检测 Empire 服务器的方法

对了对抗类似这样的检测，要 [修改 C2 的流量模式](#modifying-c2-traffic)、修改服务器登录页面、限制开放端口以及修改默认响应头

有关多种攻击框架的检测和更多相关信息，请看：
* [Empire – 修改服务器 C2 指标](http://threatexpress.com/2017/05/empire-modifying-server-c2-indicators/) - [Andrew Chiles](https://twitter.com/andrewchiles)
* [狩猎红队 Empire C2 基础设施](http://www.chokepoint.net/2017/04/hunting-red-team-empire-c2.html) - [chokepoint.net](http://www.chokepoint.net/)
* [狩猎红队 Meterpreter C2 基础设施](http://www.chokepoint.net/2017/04/hunting-red-team-meterpreter-c2.html) - [chokepoint.net](http://www.chokepoint.net/)
* [识别 Empire HTTP Listeners (Tenable 博客)](https://www.tenable.com/blog/identifying-empire-http-listeners) - [Jacob Baines](https://www.tenable.com/profile/jacob-baines)


# 保证基础设施的安全
攻击基础设施和其他联网主机一样，可能会受到攻击，并且由于其中有使用的数据和到目标环境中的连接，应该被认为是高度敏感的。

在 2016 年，常用的攻击工具中存在远程代码执行的有：

* [2016 Metasploit RCE Static Key Deserialization](https://github.com/justinsteven/advisories/blob/master/2016_metasploit_rce_static_key_deserialization.md)
* [2017 Metasploit Meterpreter Dir Traversal Bugs](https://github.com/justinsteven/advisories/blob/master/2017_metasploit_meterpreter_dir_traversal_bugs.md)
* [Empire Fails - Will Schroeder](http://www.harmj0y.net/blog/empire/empire-fails/)
* [Cobalt Strike 3.5.1 Important Security Update - Raphael Mudge](http://blog.cobaltstrike.com/2016/10/03/cobalt-strike-3-5-1-important-security-update/)

使用 **iptables** 来过滤不必要的留来那个并限制基础设施各部分间的流量。例如，如果 Cobalt Strike 团队服务器仅将 assets 提供给 Apache 的重定向器，则 iptables 规则应该只允许来自重定向器的源 IP 的 80 端口。这对于管理尤为重要，如 SSH 或 Cobalt Strike 的默认端口 50050，还要考虑阻止非目标国家 IP。作为替代，也可以考虑使用 VPS 提供商提供的防火墙，例如 Digital Ocean 提供可以保护一个或多个实例的 [Cloud Firewalls](https://www.digitalocean.com/community/tutorials/an-introduction-to-digitalocean-cloud-firewalls)

**chattr** 可以在团队服务器上使用，以防止修改 cron 目录。使用 chattr，您可以限制任何用户（包括 root）在修改文件之前删除 chattr 属性

**SSH** 应该仅限于公钥认证，并在初始登录时配置有限权限的用户，为了增加安全性，要考虑将多因子身份验证加入 SSH

**Update!** 没有安全列表是完整的，都需要定期提醒更新系统，并根据需要进行热修复来修补漏洞

当然，清单并不详尽，并没有列出所有能保护团队服务器的措施。所有基础设施都应该遵循的加固实践：

* [红帽企业 Linux 六大安全指导](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/pdf/Security_Guide/Red_Hat_Enterprise_Linux-6-Security_Guide-en-US.pdf)
* [Debian 加固文档](https://wiki.debian.org/Hardening)
* [Debian 安全加固手册](https://www.debian.org/doc/manuals/securing-debian-howto/)
* [20 Linux 服务器安全加固技巧 - nixCraft](https://www.cyberciti.biz/tips/linux-security.html)
* [SANS Linux 安全检查清单](https://www.sans.org/score/checklists/linux)
* [Docker Your Command & Control (C2)](https://blog.obscuritylabs.com/docker-command-controll-c2/) - [Alex Rymdeko-Harvey (@killswitch_gui)](https://twitter.com/killswitch_gui)

# 自动化部署
本部分涵盖的内容通常需要大量的时间来设计和实施。自动化可大大缩短部署时间，使您能够在更短的时间内部署更复杂的设置

查看有关攻击基础设施自动化的资源：
* [使用 Terraform 进行自动化基础架构部署 - Part 1](https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform---part-1/) - [@_RastaMouse](https://twitter.com/_RastaMouse)
* [Mod_Rewrite 自动化设置](https://blog.inspired-sec.com/archive/2017/04/17/Mod-Rewrite-Automatic-Setup.html) - [Julian Catrambone (@n0pe_sled)](https://twitter.com/n0pe_sled)
* [自动构建 Empire 基础设施](https://bneg.io/2017/11/06/automated-empire-infrastructure/) - [Jeremy Johnson (@beyondnegative)](https://twitter.com/beyondnegative)
* [RTOps: 使用 Ansible 自动化重定向工具部署](http://threat.tevora.com/automating-redirector-deployment-with-ansible/) - [Kevin Dick](http://threat.tevora.com/author/e0x70i/)

# 一般技巧
* **记录一切** - 运营一个复杂的 Red Team 技术设施意味着许多可移动的部件。务必记录下每个部分的功能以及流量发送的位置

* **在不同服务提供商和地区之间分割资产** - 基础设施资产应分布在多个不同的服务提供商和地理区域。Blue Team 可能会针对经常发现攻击行为的服务提供商，甚至全面封禁该服务提供商。注意：如果跨国传输加密或敏感数据，请确保遵守了国际隐私法

* **不要过分** - 如果您正在模拟特定的敌对威胁，那么最好利用技术模拟真正的威胁因素。如果 Red Team 长期攻击同一目标，请在开始使用一些“简单”的技术，并随着评估的推进，不断利用更先进的技术。随着 Blue Team 的发展，Red Team 的技术将会推动组织前进，而动用一切手段打击 Blue Team 可能会造成压倒性的局面，减缓学习进程

* **监控日志** - 在整个过程中应该监控所有日志：SMTP 日志、Apache 日志、socat 重定向工具上的 tcpdump、iptables 日志、Cobalt Strike/Empire/MSF 日志。将日志转发到中心服务器，例如使用 [rsyslog](https://bluescreenofjeff.com/2017-08-08-attack-infrastructure-log-aggregation-and-monitoring/) 进行监视。操作过程的终端数据保留用于检测历史命令的使用情况。@Killswitch_GUI 创建了一个名为 lTerm 的程序将所有 bash 终端命令记录到一个中心位置，详情参见博客 [Log all terminal output with lTerm](https://github.com/killswitch-GUI/lterm)

* **实施高价值事件警报** - 配置攻击基础设施以生成高价值事件的警报，例如新的 C2 会话或凭据捕获命中时产生警报。实现警报的一种流行方式是通过聊天平台的 API，比如 Slack。关于使用 Slack 提供警报的文章：[Slack Shell Bot - Russel Van Tuyl (@Ne0nd0g)](https://www.swordshield.com/2016/11/slackshellbot/), [Slack Notifications for Cobalt Strike - Andrew Chiles (@AndrewChiles)](http://threatexpress.com/2016/12/slack-notifications-for-cobalt-strike/), [Slack Bots for Trolls and Work - Jeff Dimmock (@bluscreenfojeff)](http://bluescreenofjeff.com/2017-04-11-slack-bots-for-trolls-and-work/)

* **指纹应急响应** - 如果可能的话，在评估开始前被动或主动地指定事件响应操作。例如，向目标发送网络钓鱼邮件（使用不相关的架构）并监视基础架构接收到的流量。应急响应团队的调查可以披露有关团队如何使用哪些基础架构。如果这些可以在评估之前就确定，则可以直接对其进行过滤或重定向。


# 感谢贡献者
非常感谢以下所有人员（按字母顺序排列），他们贡献了 wiki 中的工具、技巧或是链接，还要感谢 wiki 中提到的任何一个工具的编写者！

* [@andrewchiles - Andrew Chiles](https://twitter.com/andrewchiles)
* [@armitagehacker - Raphael Mudge](https://twitter.com/armitagehacker)
* [@beyondnegative - Jeremy Johnson](https://twitter.com/beyondnegative)
* [@bspence7337](https://twitter.com/bspence7337)
* [@domchell - Dominic Chell](https://twitter.com/domchell)
* [@jivoi - EK](https://twitter.com/jivoi)
* [@joevest - Joe Vest](https://twitter.com/joevest)
* [@killswitch_gui - Alex Rymdeko-Harvey](https://twitter.com/killswitch_gui)
* [@ne0nd0g - Russel Van Tuyl](https://twitter.com/ne0nd0g)
* [@n0pe_sled - Julian Catrambone](https://twitter.com/n0pe_sled)
* [@_RastaMouse](https://twitter.com/_RastaMouse)
* [@tifkin_ - Lee Christensen](https://twitter.com/tifkin_)
* [@Und3rf10w - Jonathan Echavarria](https://twitter.com/und3rf10w)
* [@vysecurity - Vincent Yiu](https://twitter.com/vysecurity)
* [@xorrior - Chris Ross](https://twitter.com/xorrior)
