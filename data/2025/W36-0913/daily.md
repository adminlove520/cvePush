
# 2025年09月13日 高危漏洞日报

## 概述
- 总漏洞数量: 4
- 最高CVSS评分: 7.3
- 统计时间: 2025-09-13 (UTC)


## 高危漏洞 (7.0 ≤ CVSS < 9.0) [共4个]


### CVE-2025-10358 - CVSS: 7.3

**发布时间**: 2025-09-13T08:15:26.673
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
在Wavlink WL-WN578W2 221110中检测到一个安全漏洞。这会影响/cgi-bin/wireless.cgi文件的sub_404850函数。对参数delete_list的操作导致os命令注入。攻击可以远程发起。该漏洞已被公开披露，可能会被使用。我们很早就联系了该供应商，但没有以任何方式作出回应。

#### 相关链接
https://github.com/ZZ2266/.github.io/tree/main/WAVLINK/WL-WN578W2/wireless.cgi/DeleteMac
https://github.com/ZZ2266/.github.io/tree/main/WAVLINK/WL-WN578W2/wireless.cgi/DeleteMac#proof-of-concept-poc
https://vuldb.com/?ctiid.323772


### CVE-2025-10359 - CVSS: 7.3

**发布时间**: 2025-09-13T13:15:32.190
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
在Wavlink WL-WN578W2 221110中检测到一个漏洞。这会影响/cgi-bin/wireless.cgi文件的sub_404DBC函数。对macAddr参数的操作导致os命令注入。攻击可以远程发起。这个漏洞现在是公开的，可能会被使用。我们很早就联系了该供应商，但没有以任何方式作出回应。

#### 相关链接
https://github.com/ZZ2266/.github.io/blob/main/WAVLINK/WL-WN578W2/wireless.cgi/add_mac/
https://github.com/ZZ2266/.github.io/tree/main/WAVLINK/WL-WN578W2/wireless.cgi/add_mac#proof-of-concept-poc
https://vuldb.com/?ctiid.323773


### CVE-2025-10371 - CVSS: 7.3

**发布时间**: 2025-09-13T18:15:31.717
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
在charge Hardy Barth Salia PLCC 2.2.0中发现了一个安全漏洞。这个问题影响了/api.php文件的一些未知处理。参数setrfidlist的操作导致无限制上传。攻击可以从远程执行。该漏洞已向公众发布，可能会被利用。我们很早就联系了该供应商，但没有以任何方式作出回应。

#### 相关链接
https://github.com/YZS17/CVE/blob/main/Salia_PLCC/file-write-api.php.md
https://github.com/YZS17/CVE/blob/main/Salia_PLCC/file-write-api.php.md#poc
https://vuldb.com/?ctiid.323779


### CVE-2025-10374 - CVSS: 7.3

**发布时间**: 2025-09-13T19:15:31.650
**攻击向量**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
**漏洞分类**: 高危


#### 漏洞描述
深圳思讯7/11业务管理系统存在安全漏洞。这会影响文件/Adm/OperatorStop的未知部分。操作将导致不正确的授权。这种攻击有可能远程实施。该漏洞已向公众发布，可能会被利用。

#### 相关链接
https://vuldb.com/?ctiid.323788
https://vuldb.com/?id.323788
https://vuldb.com/?submit.639092



## 数据来源
- NVD (National Vulnerability Database)

---
*本报告由 CVE Push Service 自动生成*"
