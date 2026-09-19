// Demo email samples with realistic headers and content

export interface DemoEmail {
  id: string;
  name: string;
  description: string;
  riskScore: number;
  riskLevel: 'safe' | 'low' | 'suspicious' | 'high' | 'critical';
  from: string;
  to: string;
  subject: string;
  date: string;
  messageId: string;
  rawHeaders: string;
  body: string;
}

export const demoEmails: DemoEmail[] = [
  {
    id: 'demo-1',
    name: 'Legitimate email',
    description: 'Your Microsoft 365 security summary',
    riskScore: 7,
    riskLevel: 'safe',
    from: 'security-noreply@microsoft.com',
    to: 'alex.morgan@acmecorp.com',
    subject: 'Your Microsoft 365 security summary',
    date: 'Wed, 26 Aug 2026 09:15:22 +0000',
    messageId: '<m365-security-82736481@microsoft.com>',
    rawHeaders: `Delivered-To: alex.morgan@acmecorp.com
Received: from mail-eopbgr110052.outbound.protection.outlook.com (mail-eopbgr110052.outbound.protection.outlook.com [40.107.11.52])
        by mx.acmecorp.com with ESMTPS id x12si5461927ejb.224.2026.08.26.02.15.21
        for <alex.morgan@acmecorp.com>
        Wed, 26 Aug 2026 02:15:21 -0700 (PDT)
Received: from DU0P191CA0001.EURP191.PROD.OUTLOOK.COM (2603:10a6:10:12f::9) by
 DU0PR01MB6524.eurprd01.prod.exchangelabs.com (2603:10a6:10:16e::21) with
 Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
 id 15.20.7897.11
Authentication-Results: spf=pass (sender IP is 40.107.11.52)
 smtp.mailfrom=microsoft.com; dkim=pass (signature was verified)
 header.d=microsoft.com; dmarc=pass action=none header.from=microsoft.com;
Return-Path: <security-noreply@microsoft.com>
From: Microsoft Account <security-noreply@microsoft.com>
To: alex.morgan@acmecorp.com
Subject: Your Microsoft 365 security summary
Date: Wed, 26 Aug 2026 09:15:22 +0000
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
X-Mailer: Microsoft Exchange Server 15.20.7897.011
Message-ID: <m365-security-82736481@microsoft.com>`,
    body: `Dear Alex Morgan,

Here is your monthly Microsoft 365 security summary for August 2026.

Security Score: 82/100 (+3 from last month)

Recent Activity:
- 3 suspicious sign-in attempts blocked
- Multi-factor authentication: Active
- Last sign-in: Aug 26, 2026 from Dublin, Ireland

No action required. Your account is secure.

To review your security settings, visit https://account.microsoft.com/security

Microsoft Corporation | One Microsoft Way, Redmond, WA 98052`
  },
  {
    id: 'demo-2',
    name: 'Credential phishing',
    description: 'Action required: verify your payroll account',
    riskScore: 86,
    riskLevel: 'critical',
    from: 'payroll@microsOft-support.com',
    to: 'alex.morgan@acmecorp.com',
    subject: 'Action required: verify your payroll account',
    date: 'Wed, 26 Aug 2026 10:18:05 +0100',
    messageId: '<7f3k9p2@microsOft-support.com>',
    rawHeaders: `Delivered-To: alex.morgan@acmecorp.com
Received: from mail.microsOft-support.com (5.188.210.46)
        by mx.acmecorp.com with ESMTPS id p3si7291827plb.183.2026.08.26.02.18.04
        Wed, 26 Aug 2026 02:18:04 -0700 (PDT)
Received: from [10.0.0.12] (unknown [185.220.101.46])
        by mail.microsOft-support.com (Postfix) with ESMTP id 3A1F28A4C2
        Wed, 26 Aug 2026 10:18:01 +0100 (BST)
Authentication-Results: spf=fail (sender IP is 185.220.101.46)
 smtp.mailfrom=microsOft-support.com; dkim=fail (no key for signature)
 header.d=microsOft-support.com; dmarc=fail action=quarantine header.from=microsOft-support.com;
Return-Path: <bounce@microsOft-support.com>
From: Microsoft Payroll <payroll@microsOft-support.com>
Reply-To: payroll-verify@proton-example.com
To: alex.morgan@acmecorp.com
Subject: Action required: verify your payroll account
Date: Wed, 26 Aug 2026 10:18:05 +0100
X-Mailer: PHPMailer 6.4.1
Message-ID: <7f3k9p2@microsOft-support.com>`,
    body: `URGENT: Your payroll account requires immediate verification.

Dear Employee,

We have detected unusual activity on your Microsoft payroll account. 
To avoid disruption to your salary payment, please verify your credentials immediately.

⚠️ FAILURE TO VERIFY WITHIN 24 HOURS WILL RESULT IN PAYMENT SUSPENSION ⚠️

Click here to verify your account:
https://microsOft-support.com/payroll/verify?token=a7f3k9p2&redirect=https://acmecorp.com

After verification, update your banking details to ensure continuous payment.

Microsoft Payroll Security Team`
  },
  {
    id: 'demo-3',
    name: 'Business Email Compromise',
    description: 'Urgent Vendor Payment Approval',
    riskScore: 94,
    riskLevel: 'critical',
    from: 'ceo@micros0ft-secure.com',
    to: 'finance@acmecorp.com',
    subject: 'Urgent Vendor Payment Approval',
    date: 'Wed, 26 Aug 2026 11:45:33 +0800',
    messageId: '<ceo-urgent-882@micros0ft-secure.com>',
    rawHeaders: `Delivered-To: finance@acmecorp.com
Received: from mail.micros0ft-secure.com (185.231.72.12)
        by mx.acmecorp.com with ESMTP id k8si2917834pjf.122.2026.08.26.03.45.32
        Wed, 26 Aug 2026 03:45:32 -0700 (PDT)
Received: from [10.14.0.5] (unknown [185.231.72.12])
        by mail.micros0ft-secure.com (Postfix) with SMTP id 9B2C14C891
        Wed, 26 Aug 2026 11:45:29 +0800 (SGT)
Received: from relay.104.18.24.10 (Frankfurt, Germany)
        by mail.micros0ft-secure.com
        Wed, 26 Aug 2026 11:45:31 +0800 (SGT)
Authentication-Results: spf=fail (sender IP is 185.231.72.12)
 smtp.mailfrom=micros0ft-secure.com; dkim=pass (signature was verified but domain age is 3 days)
 header.d=micros0ft-secure.com; dmarc=fail action=reject header.from=micros0ft-secure.com;
 compauth=fail reason=001
Return-Path: <bounce@micros0ft-secure.com>
From: CEO <ceo@micros0ft-secure.com>
Reply-To: finance.verify@proton-example.com
To: finance@acmecorp.com
CC: 
Subject: Urgent Vendor Payment Approval
Date: Wed, 26 Aug 2026 11:45:33 +0800
Importance: high
X-Priority: 1
X-Originating-IP: 185.231.72.12
X-Mailer: Microsoft Outlook 16.0
Message-ID: <ceo-urgent-882@micros0ft-secure.com>`,
    body: `Hi,

I need you to process an urgent wire transfer today. Our strategic vendor has sent a final notice and we need to clear this by EOD to maintain the relationship.

Amount: USD 87,500
Beneficiary: Global Trade Solutions Pte Ltd
Bank: DBS Bank Singapore
Account: 017-903821-0
SWIFT: DBSSSGSG

This is confidential. Please do not discuss with other team members until confirmed. I am in a board meeting all day and will not be reachable by phone. Process this through email only.

Reply to this email to confirm once done.

Best,
Satya Nadella
Chief Executive Officer
Microsoft Corporation`
  }
];
