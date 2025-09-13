
# 2025年09月13日 高危漏洞日报

## 概述
- 总漏洞数量: 1
- 最高CVSS评分: 7.3
- 统计时间: 2025-09-13 (UTC)


## 高危漏洞 (7.0 ≤ CVSS < 9.0) [共1个]


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



## 数据来源
- NVD (National Vulnerability Database)

---
*本报告由 CVE Push Service 自动生成*"
