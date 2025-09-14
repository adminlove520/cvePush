
# 2025年09月14日 高危漏洞日报

## 概述
- 总漏洞数量: 8
- 最高CVSS评分: 9.8
- 统计时间: 2025-09-14 (UTC)


## 严重漏洞 (CVSS ≥ 9.0) [共1个]


### CVE-2025-10392 - CVSS: 9.8

**发布时间**: 2025-09-14T06:15:29.487
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**漏洞分类**: 严重


#### 漏洞描述
在Mercury KM08-708H Wifi Wave 2 1.1.14中检测到漏洞。这会影响组件HTTP标头处理程序的未知功能。参数主机的操作导致基于堆栈的缓冲区溢出。攻击可以远程执行。利用现在是公开的，可以使用。

#### 相关链接
https://github.com/mohdkey/IOT-CVE/blob/main/KT_GIGA_WIFI-Wave%202%20has%20a%20stack%20overflow%20vulnerability.pdf
https://vuldb.com/?ctiid.323827
https://vuldb.com/?id.323827


## 高危漏洞 (7.0 ≤ CVSS < 9.0) [共7个]


### CVE-2025-10385 - CVSS: 8.8

**发布时间**: 2025-09-14T01:15:31.433
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
**漏洞分类**: 高危


#### 漏洞描述
水星KM08-708H GiGA WiFi Wave2 1.1存在漏洞。受此问题影响的是/goform/mcr_setSysAdm文件的sub_450B2C函数。对参数ChgUserId的操作会导致缓冲区溢出。可以远程发起攻击。这个漏洞已经向公众披露，可能会被利用。

#### 相关链接
https://github.com/Jjx-wy/kt/blob/main/KT%20KM08-708H.md
https://vuldb.com/?ctiid.323820
https://vuldb.com/?id.323820


### CVE-2025-59363 - CVSS: 7.7

**发布时间**: 2025-09-14T05:15:31.680
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N
**漏洞分类**: 高危


#### 漏洞描述
在2025年3.0之前的One Identity OneLogin中，请求使用GET Apps API v2返回OIDC客户端秘密（即使这个秘密应该只在应用程序第一次创建时返回）。

#### 相关链接
https://onelogin.service-now.com/support?id=kb_article&sys_id=b0aad1e11bd3ea109a47ec29b04bcb72&kb_category=a0d76d70db185340d5505eea4b96199f


### CVE-2025-10396 - CVSS: 7.3

**发布时间**: 2025-09-14T09:15:31.753
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
sourcecoster宠物美容管理软件1.0存在漏洞。受此问题影响的是/admin/edit_role.php文件的一些未知功能。执行对参数ID的操作可能导致sql注入。可以远程发起攻击。该漏洞已被公开披露，并可能被利用。

#### 相关链接
https://github.com/zhe293/src2/blob/master/report.md
https://vuldb.com/?ctiid.323831
https://vuldb.com/?id.323831


### CVE-2025-10402 - CVSS: 7.3

**发布时间**: 2025-09-14T17:15:33.163
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
PHPGurukul美容院管理系统1.1存在漏洞。受影响的元素是/admin/readenq.php文件的未知函数。执行对参数delid的操作可能导致sql注入。攻击可以远程执行。该漏洞已经发布，可能会被使用。

#### 相关链接
https://github.com/LitBot123/mycve/issues/6
https://phpgurukul.com/
https://vuldb.com/?ctiid.323837


### CVE-2025-10403 - CVSS: 7.3

**发布时间**: 2025-09-14T18:15:32.153
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
PHPGurukul美容院管理系统1.1存在漏洞。这会影响文件/admin/view- query .php的一个未知函数。对参数视图的操作导致sql注入。这种攻击有可能远程实施。这个漏洞已经向公众披露，可能会被利用。

#### 相关链接
https://github.com/LitBot123/mycve/issues/7
https://phpgurukul.com/
https://vuldb.com/?ctiid.323838


### CVE-2025-10404 - CVSS: 7.3

**发布时间**: 2025-09-14T18:15:33.067
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
在其洗礼信息管理系统1.0源代码中发现一个漏洞。这会影响/rptbaptism .php文件的一个未知函数。对参数ID的操作导致sql注入。攻击可以从远程执行。这个漏洞已经公开，可以使用。

#### 相关链接
https://github.com/peri0d/my_cve/issues/5
https://itsourcecode.com/
https://vuldb.com/?ctiid.323839


### CVE-2025-10405 - CVSS: 7.3

**发布时间**: 2025-09-14T19:15:33.623
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
在其IRCECODE洗礼信息管理系统1.0中确定了漏洞。受影响是文件 /listbaptism.php的未知功能。该论点的这种操作BAPT_ID导致SQL注入。可以远程发动攻击。该漏洞已公开披露并可能被使用。

#### 相关链接
https://github.com/peri0d/my_cve/issues/4
https://itsourcecode.com/
https://vuldb.com/?ctiid.323840



## 数据来源
- NVD (National Vulnerability Database)

---
*本报告由 CVE Push Service 自动生成*"
