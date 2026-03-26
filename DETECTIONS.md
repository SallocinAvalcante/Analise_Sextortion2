# DETECTIONS.md — Sextortion Campaign Detection Rules

> Regras de detecção baseadas nos TTPs identificados durante a investigação desta campanha e da campanha anterior correlacionada.
> Formato: **Sigma** — conversível para qualquer SIEM via [Uncoder.IO](https://tdm.socprime.com/uncoder-ai/translate)

---

## Índice

1. [SPF FAIL + DMARC FAIL originado de ASN de datacenter](#1-spf-fail--dmarc-fail-originado-de-asn-de-datacenter)
2. [Spoofing via Return-Path divergente do From](#2-spoofing-via-return-path-divergente-do-from)
3. [E-mail contendo endereço Bitcoin em corpo de mensagem](#3-e-mail-contendo-endereço-bitcoin-em-corpo-de-mensagem)
4. [IP de envio pertencente ao range DigitalOcean — campanha 1](#4-ip-de-envio-pertencente-ao-range-digitalocean--campanha-1)
5. [IP de envio pertencente ao range DigitalOcean — campanha 2](#5-ip-de-envio-pertencente-ao-range-digitalocean--campanha-2)
6. [Domínios de infraestrutura conhecidos da campanha](#6-domínios-de-infraestrutura-conhecidos-da-campanha)
7. [Carteiras Bitcoin conhecidas da campanha](#7-carteiras-bitcoin-conhecidas-da-campanha)
8. [Padrão combinado de alta confiança — Sextortion](#8-padrão-combinado-de-alta-confiança--sextortion)

---

## 1. SPF FAIL + DMARC FAIL originado de ASN de datacenter

**Objetivo:** detectar e-mails com falha dupla de autenticação (SPF + DMARC), característicos do padrão de spoofing desta campanha.

```yaml
title: Email SPF and DMARC Failure from Datacenter ASN
id: a1b2c3d4-0001-4e5f-a6b7-c8d9e0f10001
status: experimental
description: >
  Detects inbound emails failing both SPF and DMARC authentication,
  originating from known datacenter ASNs (DigitalOcean AS14061).
  Consistent with sextortion and phishing campaigns abusing domains
  with missing or misconfigured email security policies.
author: Nicollas Cavalcante Souza
date: 2026/03/19
references:
  - https://github.com/YOUR_REPO/sextortion-analysis
tags:
  - attack.initial_access
  - attack.t1566.001  # Phishing: Spearphishing Attachment
  - attack.t1566.002  # Phishing: Spearphishing Link
  - attack.t1598      # Phishing for Information
logsource:
  category: email
  product: exchange
  # Compatible with: Microsoft Exchange, Proofpoint, Mimecast, Google Workspace
detection:
  selection:
    AuthenticationResults|contains:
      - 'spf=fail'
      - 'spf=none'
    AuthenticationResults|contains:
      - 'dmarc=fail'
  filter_internal:
    SenderIPAddress|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
  condition: selection and not filter_internal
falsepositives:
  - Legitimate third-party senders with misconfigured SPF/DMARC
  - Forwarded emails breaking authentication chain
level: medium
fields:
  - SenderIPAddress
  - SenderDomain
  - ReturnPath
  - Subject
  - RecipientAddress
```

---

## 2. Spoofing via Return-Path divergente do From

**Objetivo:** identificar casos em que o domínio do `Return-Path` (envelope sender) difere do domínio declarado no `From`, indicador direto de spoofing.

```yaml
title: Email Return-Path Domain Mismatch — Spoofing Indicator
id: a1b2c3d4-0002-4e5f-a6b7-c8d9e0f10002
status: experimental
description: >
  Detects emails where the Return-Path domain does not match the
  From header domain, a direct indicator of email spoofing.
  In the investigated campaigns, the attacker used legitimately-owned
  subdomains (e.g., hexane@dash.zeeklabs.com) as Return-Path while
  spoofing unrelated From addresses.
author: Nicollas Cavalcante Souza
date: 2026/03/19
references:
  - https://github.com/YOUR_REPO/sextortion-analysis
tags:
  - attack.initial_access
  - attack.t1566
  - attack.t1036  # Masquerading
logsource:
  category: email
  product: exchange
detection:
  selection_spf_fail:
    AuthenticationResults|contains:
      - 'spf=fail'
      - 'spf=none'
  selection_dmarc_fail:
    AuthenticationResults|contains: 'dmarc=fail'
  selection_return_path:
    ReturnPath|contains:
      - 'zeeklabs.com'
      - 'brighterfuture.net'
  condition: selection_spf_fail and selection_dmarc_fail and selection_return_path
falsepositives:
  - Bulk mailing services with legitimate Return-Path routing
level: high
fields:
  - From
  - ReturnPath
  - SenderIPAddress
  - Subject
```

---

## 3. E-mail contendo endereço Bitcoin em corpo de mensagem

**Objetivo:** detectar e-mails cujo corpo contenha padrões de endereço Bitcoin, característica central de campanhas de extorsão financeira.

```yaml
title: Email Body Contains Bitcoin Address — Extortion Pattern
id: a1b2c3d4-0003-4e5f-a6b7-c8d9e0f10003
status: experimental
description: >
  Detects inbound emails containing Bitcoin address patterns in the body.
  This is a core indicator of sextortion and extortion campaigns demanding
  cryptocurrency payments. Addresses may follow Legacy (1xxx), P2SH (3xxx),
  or SegWit (bc1q/bc1p) formats.
author: Nicollas Cavalcante Souza
date: 2026/03/19
references:
  - https://github.com/YOUR_REPO/sextortion-analysis
tags:
  - attack.impact
  - attack.t1657  # Financial Theft
  - attack.t1566
logsource:
  category: email
  product: exchange
detection:
  selection_btc_legacy:
    Body|re: '1[a-zA-Z0-9]{25,34}'
  selection_btc_p2sh:
    Body|re: '3[a-zA-Z0-9]{25,34}'
  selection_btc_segwit:
    Body|re: 'bc1[a-z0-9]{6,87}'
  selection_keywords:
    Body|contains:
      - 'Bitcoin'
      - 'BTC'
      - 'cryptocurrency'
      - 'wallet address'
      - 'blockchain'
  condition: (selection_btc_legacy or selection_btc_p2sh or selection_btc_segwit) and selection_keywords
falsepositives:
  - Legitimate cryptocurrency-related newsletters or exchanges
  - Bitcoin payment confirmation emails
level: medium
fields:
  - From
  - ReturnPath
  - SenderIPAddress
  - Subject
  - Body
```

---

## 4. IP de envio pertencente ao range DigitalOcean — campanha 1

**Objetivo:** detectar e-mails originados do IP identificado na primeira campanha investigada.

```yaml
title: Email from Known Malicious IP — Sextortion Campaign 1 (brighterfuture.net)
id: a1b2c3d4-0004-4e5f-a6b7-c8d9e0f10004
status: stable
description: >
  Detects inbound emails originating from IP 164.92.68.246, associated with
  the first investigated sextortion campaign using brighterfuture.net as SMTP
  infrastructure. IP reported on AbuseIPDB (27/02/2026 and 15/03/2026).
  Infrastructure remained active as of 19/03/2026.
author: Nicollas Cavalcante Souza
date: 2026/03/19
references:
  - https://github.com/YOUR_REPO/sextortion-analysis
tags:
  - attack.initial_access
  - attack.t1566
logsource:
  category: email
  product: exchange
detection:
  selection:
    SenderIPAddress: '164.92.68.246'
  condition: selection
falsepositives:
  - None expected for this specific IP
level: high
fields:
  - From
  - ReturnPath
  - SenderIPAddress
  - Subject
  - RecipientAddress
```

---

## 5. IP de envio pertencente ao range DigitalOcean — campanha 2

**Objetivo:** detectar e-mails originados do IP identificado nesta campanha.

```yaml
title: Email from Known Malicious IP — Sextortion Campaign 2 (zeeklabs.com)
id: a1b2c3d4-0005-4e5f-a6b7-c8d9e0f10005
status: stable
description: >
  Detects inbound emails originating from IP 67.205.157.219, associated with
  the second investigated sextortion campaign abusing the zeeklabs.com domain
  as SMTP infrastructure (HELO/EHLO identity: dash.zeeklabs.com).
  DigitalOcean VPS — ASN AS14061.
author: Nicollas Cavalcante Souza
date: 2026/03/19
references:
  - https://github.com/YOUR_REPO/sextortion-analysis
tags:
  - attack.initial_access
  - attack.t1566
logsource:
  category: email
  product: exchange
detection:
  selection:
    SenderIPAddress: '67.205.157.219'
  condition: selection
falsepositives:
  - None expected for this specific IP
level: high
fields:
  - From
  - ReturnPath
  - SenderIPAddress
  - Subject
  - RecipientAddress
```

---

## 6. Domínios de infraestrutura conhecidos da campanha

**Objetivo:** detectar comunicação de rede (DNS, HTTP, SMTP) com domínios de infraestrutura identificados nas duas campanhas.

```yaml
title: Network Communication with Known Sextortion Campaign Infrastructure
id: a1b2c3d4-0006-4e5f-a6b7-c8d9e0f10006
status: stable
description: >
  Detects DNS queries or network connections to domains associated with
  sextortion campaign infrastructure identified across two separate
  investigations. Includes SMTP subdomains, campaign domains and
  suspected DGA domain (licftluimc.quest).
author: Nicollas Cavalcante Souza
date: 2026/03/19
references:
  - https://github.com/YOUR_REPO/sextortion-analysis
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1566
logsource:
  category: dns
  product: any
detection:
  selection:
    dns.question.name|contains:
      - 'zeeklabs.com'
      - 'dash.zeeklabs.com'
      - 'brighterfuture.net'
      - 'api.brighterfuture.net'
      - 'licftluimc.quest'
  condition: selection
falsepositives:
  - zeeklabs.com may generate FPs if organization has legitimate relationship with this domain
  - Review context before blocking zeeklabs.com at DNS level
level: medium
fields:
  - dns.question.name
  - source.ip
  - host.name
```

---

## 7. Carteiras Bitcoin conhecidas da campanha

**Objetivo:** detectar menções ou consultas a carteiras Bitcoin identificadas na investigação, útil em ferramentas de monitoramento de e-mail, proxies ou sistemas de DLP.

```yaml
title: Known Sextortion Bitcoin Wallet Address Observed
id: a1b2c3d4-0007-4e5f-a6b7-c8d9e0f10007
status: stable
description: >
  Detects presence of known Bitcoin wallet addresses associated with
  the investigated sextortion campaign in email bodies, web traffic,
  or document content. Addresses include the primary collection wallet
  and all traced downstream wallets across Path A and Path B.
author: Nicollas Cavalcante Souza
date: 2026/03/19
references:
  - https://github.com/YOUR_REPO/sextortion-analysis
tags:
  - attack.impact
  - attack.t1657
logsource:
  category: email
  product: exchange
  # Also applicable to: proxy, DLP, CASB
detection:
  selection:
    Body|contains:
      # Primary wallet
      - '1LW9aVXFeEpGaqDaugFj6UoYfPBWvsLHPv'
      # Inbound
      - '1G47mSr3oANXMafVrR8UC4pzV7FEAzo3r9'
      - 'bc1qps9458ydk8y9vlu5h0keeyh2ls0q5vruq7r58zruq9hpudlsywhqmelfhx'
      - 'bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h'
      # Path A
      - '15LjopQSGEciscSofebUkPu44yXPQah5tV'
      - '1PZ4sWYFR2YL8HrXWJ9MNgpYQGoQ1D4s99'
      - 'bc1qdn3935jtfpyvdj6rv3wm078ekne7a2epzv9rav'
      - 'bc1q0kq7rd5ncpvy59v3rk9f8uuj0easp6mk40lzxx'
      - '15tvZEg89vXyqkkG4zaz4DRdFi7B1RCSP8'
      # Path B
      - 'bc1q4g37wkvgppcg5qru8gudnqf3qjqcej4a966ct8'
      - 'bc1qcpwhs4nj30zvnx7x8cyt9n3996easp58shuuc2'
      - 'bc1qn0k7de535rk975zsvukp6rwcarm5fwmu9zu9l5'
      - '3Cb2BhNPD9YNaEvgXAHS1EZNAjqyxGS56s'
      - 'bc1q9wvygkq7h9xgcp59mc6ghzczrqlgrj9k3ey9tz'
  condition: selection
falsepositives:
  - Threat intelligence platforms indexing these wallets
  - Security research tools referencing IOCs
level: critical
fields:
  - From
  - ReturnPath
  - Subject
  - Body
  - RecipientAddress
```

---

## 8. Padrão combinado de alta confiança — Sextortion

**Objetivo:** regra de alta confiança que combina múltiplos indicadores simultâneos para reduzir falsos positivos e sinalizar campanhas ativas com alta precisão.

```yaml
title: High-Confidence Sextortion Email Pattern — Combined Indicators
id: a1b2c3d4-0008-4e5f-a6b7-c8d9e0f10008
status: experimental
description: >
  High-confidence detection combining authentication failures, known
  datacenter ASN origin, Bitcoin address presence and sextortion keyword
  patterns. Designed to minimize false positives while catching active
  campaigns matching the investigated playbook. Correlates TTPs from
  both investigated campaigns sharing DigitalOcean (AS14061) infrastructure.
author: Nicollas Cavalcante Souza
date: 2026/03/19
references:
  - https://github.com/YOUR_REPO/sextortion-analysis
tags:
  - attack.initial_access
  - attack.impact
  - attack.t1566
  - attack.t1657
logsource:
  category: email
  product: exchange
detection:
  selection_auth_fail:
    AuthenticationResults|contains|all:
      - 'dmarc=fail'
  selection_auth_spf:
    AuthenticationResults|contains:
      - 'spf=fail'
      - 'spf=none'
  selection_btc:
    Body|contains:
      - 'Bitcoin'
      - 'BTC'
      - 'wallet'
  selection_btc_address:
    Body|re: '(1[a-zA-Z0-9]{25,34}|3[a-zA-Z0-9]{25,34}|bc1[a-z0-9]{6,87})'
  selection_extortion_keywords:
    Body|contains:
      - 'password'
      - 'camera'
      - 'compromised'
      - 'hacked'
      - 'recorded'
      - 'pay'
      - 'hours'
      - 'do not reply'
  condition: >
    selection_auth_fail and
    selection_auth_spf and
    selection_btc and
    selection_btc_address and
    selection_extortion_keywords
falsepositives:
  - Extremely unlikely given the combination of conditions required
level: critical
fields:
  - From
  - ReturnPath
  - SenderIPAddress
  - Subject
  - Body
  - RecipientAddress
```

---

## Notas de Implementação

### Conversão para SIEM

Todas as regras acima podem ser convertidas para os principais SIEMs via [Uncoder.IO](https://tdm.socprime.com/uncoder-ai/translate):

| SIEM | Suporte |
|---|---|
| Microsoft Sentinel (KQL) | ✅ |
| Splunk SPL | ✅ |
| Elastic SIEM (EQL) | ✅ |
| IBM QRadar AQL | ✅ |
| Chronicle YARA-L | ✅ |
| Datadog | ✅ |

### Ajustes de campos por ambiente

Os campos utilizados nas regras (`SenderIPAddress`, `AuthenticationResults`, `ReturnPath`, `Body`) seguem a nomenclatura padrão do **Microsoft Exchange Message Tracking**. Para outros ambientes, pode ser necessário adaptar:

| Campo padrão | Exchange | Google Workspace | Proofpoint |
|---|---|---|---|
| IP de origem | `SenderIPAddress` | `ip` | `senderIP` |
| Resultado SPF | `AuthenticationResults` | `spf` | `spf` |
| Return-Path | `ReturnPath` | `return_path` | `returnPath` |

### Prioridade de implantação sugerida

1. 🔴 **Crítico** — Regras 4, 5 (IPs específicos conhecidos) e 7 (carteiras conhecidas)
2. 🟠 **Alto** — Regra 8 (padrão combinado) e Regra 2 (Return-Path mismatch)
3. 🟡 **Médio** — Regras 1, 3, 6 (indicadores genéricos de campanha)

---

## ⚠️ Disclaimer

Regras desenvolvidas com base em análise OSINT para fins educacionais e de threat intelligence defensiva. Adaptar thresholds e campos conforme o ambiente de implantação.
