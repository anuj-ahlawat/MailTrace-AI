"""Bounded, ten-page presentation of immutable forensic report snapshots.

No network, collection, scoring or database operations belong in this module.
Every page has a fixed content budget; omitted rows are disclosed, never scaled
into unreadable text. All presentation transformations leave the snapshot intact.
"""
from collections import Counter
from html import escape
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
from datetime import datetime
import math

import reportlab
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Paragraph, Table, TableStyle, Flowable

NA = 'Not Available'
WIDTH, HEIGHT, MARGIN = 595.28, 841.89, 44
CONTENT = WIDTH - MARGIN * 2
NAVY, BLUE, MUTED = '#12263b', '#176b91', '#52667b'
SEVERITY = {'CRITICAL': '#ab2938', 'HIGH': '#ad491b', 'MEDIUM': '#946400', 'LOW': '#28724f'}
TITLES = [
    ('Executive Summary', 'What requires the investigator\'s attention?'),
    ('Email Overview', 'What message was examined?'),
    ('AI Threat Analysis', 'What did the model predict, and why?'),
    ('Email Authentication', 'What was reported, and what was independently checked?'),
    ('Header & Relay Forensics', 'What path is visible in the supplied headers?'),
    ('IOC Analysis', 'Which observed indicators warrant review?'),
    ('Threat Intelligence', 'What do the available providers report?'),
    ('Probable Network Origin', 'What network infrastructure can be located?'),
    ('Explainable Risk Score', 'Which recorded contributions produced the final score?'),
    ('Investigation Conclusion', 'What is supported, and what should happen next?'),
]


def number(value):
    try:
        value = float(value)
        return value if math.isfinite(value) else None
    except (TypeError, ValueError):
        return None


def text(value, limit=180):
    """Bound and escape only at render time; never change evidence values."""
    if value is None or value == '':
        return NA
    if isinstance(value, (dict, list)):
        return 'Structured evidence - see JSON'
    value = ' '.join(str(value).split())
    value = value.replace('\u2014', ' - ').replace('\u2013', '-').replace('\u2011', '-').replace('\u2192', '->')
    if len(value) > limit:
        value = value[:max(0, limit - 3)].rsplit(' ', 1)[0] + '...'
    return value


def unique(items, key):
    seen, result = set(), []
    for item in items:
        identity = key(item)
        if identity not in seen:
            seen.add(identity)
            result.append(item)
    return result


def short_url(value):
    try:
        parsed = urlsplit(str(value or ''))
        # Never render credentials, tracking queries or fragments in the PDF.
        host = parsed.hostname or ''
        return text(host, 48) + ('/...' if parsed.path or parsed.query or parsed.fragment else '')
    except ValueError:
        return 'Malformed URL - see JSON'


def percentage(value):
    value = number(value)
    return f'{value * 100:.2f}%' if value is not None else NA


class View:
    """Select one consistent email across parallel legacy snapshot sections."""
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.sections = snapshot.get('sections') or {}
        scores = self.sections.get('Risk Score') or []
        self.index = max(range(len(scores)), key=lambda i: number(scores[i].get('score')) if number(scores[i].get('score')) is not None else -1, default=0)
        self.email_id = self.get('Risk Score').get('email_id')

    def get(self, section):
        rows = self.sections.get(section) or []
        if isinstance(rows, dict):
            return rows
        return (rows[self.index] or {}) if self.index < len(rows) else {}

    def value(self, section):
        return self.get(section).get('value')

    @property
    def raw(self):
        return next((a.get('forensics') or {} for a in self.snapshot.get('analyses', []) if a.get('email_id') == self.email_id), {})

    @property
    def intel(self):
        return self.get('Threat Intelligence').get('results') or []

    @property
    def geos(self):
        return unique([p for p in (self.get('Geolocation').get('results') or []) if p.get('status') == 'Available'], lambda p: p.get('query'))

    @property
    def urls(self):
        return unique(self.value('URL Analysis') or [], lambda u: u.get('original_url') or u.get('url'))

    @property
    def attachments(self):
        return unique(self.value('Attachment Analysis') or [], lambda a: (a.get('sha256'), a.get('filename')))

    @property
    def iocs(self):
        values = list(self.raw.get('iocs') or [])
        values += [{'type': i.get('type'), 'value': i.get('query')} for i in self.intel]
        values += [{'type': 'url', 'value': u.get('original_url')} for u in self.urls]
        values += [{'type': 'domain', 'value': u.get('domain')} for u in self.urls]
        identity = self.value('Sender Identity Analysis') or {}
        values += [{'type': 'domain', 'value': identity.get(k)} for k in ('sender_domain', 'reply_to_domain', 'return_path_domain')]
        values += [{'type': 'ip', 'value': ip.get('ip')} for h in self.value('Received Path') or [] for ip in h.get('ips') or []]
        values += [{'type': 'ip', 'value': h.get('ip')} for h in self.get('Geolocation').get('analyzed_hops') or []]
        return unique([i for i in values if i.get('value')], lambda i: (i.get('type'), i.get('value')))


def vt_stats(provider):
    result = provider.get('result') or {}
    attrs = (result.get('data') or {}).get('attributes') or {}
    return attrs.get('last_analysis_stats') or result.get('last_analysis_stats') or {}, attrs.get('reputation', result.get('reputation'))


def provider_summary(provider):
    status, name = provider.get('status'), provider.get('provider')
    if status != 'Available':
        return text(status) + ': ' + text(provider.get('reason'), 85)
    result = provider.get('result') or {}
    if name == 'virustotal':
        stats, reputation = vt_stats(provider)
        return '; '.join(f'{label}: {text(stats.get(key))}' for key, label in [('malicious', 'Malicious'), ('suspicious', 'Suspicious'), ('harmless', 'Harmless'), ('undetected', 'Undetected')]) + '; Reputation: ' + text(reputation)
    if name == 'abuseipdb':
        data = result.get('data') or result
        return f'Abuse confidence: {text(data.get("abuseConfidenceScore"))}%; reports: {text(data.get("totalReports"))}'
    if name == 'greynoise':
        return 'Classification: ' + text(result.get('classification'))
    if name == 'urlscan':
        return f'Search results: {text(result.get("total"))}; contextual results, not a verdict'
    return 'Available; full provider evidence in JSON'


def reputation(view, value):
    for item in view.intel:
        if item.get('query') == value:
            providers = [p for p in item.get('providers') or [] if p.get('provider') in ('virustotal', 'abuseipdb', 'greynoise') and p.get('status') == 'Available']
            if providers:
                return text(providers[0].get('provider')) + ': ' + provider_summary(providers[0])
    return NA


def priority(item):
    """Surface provider detections first without converting them into certainty."""
    score = 0
    for p in item.get('providers') or []:
        if p.get('status') != 'Available':
            continue
        if p.get('provider') == 'virustotal':
            stats, _ = vt_stats(p)
            score += (number(stats.get('malicious')) or 0) * 10 + (number(stats.get('suspicious')) or 0)
        elif p.get('provider') == 'abuseipdb':
            score += (number(((p.get('result') or {}).get('data') or {}).get('abuseConfidenceScore')) or 0) / 10
        elif p.get('provider') == 'greynoise' and (p.get('result') or {}).get('classification') == 'malicious':
            score += 10
    return score


def score_value(row):
    return row.get('score') if row.get('score') is not None else row.get('risk_score')


def score_severity(view):
    row = view.get('Risk Score')
    if row.get('severity'):
        return row['severity']
    # Historical exports often omitted thresholds and severity. Do not apply
    # today's configuration retroactively to that evidence.
    thresholds = (row.get('scoring_policy') or {}).get('thresholds')
    score = number(score_value(row))
    if thresholds and len(thresholds) == 3 and score is not None:
        return next((label for label, threshold in reversed(list(zip(['MEDIUM', 'HIGH', 'CRITICAL'], thresholds))) if score >= threshold), 'LOW')
    return 'UNKNOWN'


def verification(value):
    status = value.get('status') if isinstance(value, dict) else None
    return 'PASS (VERIFIED)' if status == 'PASS' else 'FAIL' if status == 'FAIL' else 'Verification unavailable' + (f' ({text(status, 24)})' if status else '')


def alignment(value):
    return 'ALIGNED (observed)' if value is True else 'NOT ALIGNED (observed)' if value is False else 'UNKNOWN'


def findings(view):
    ml, risk = view.get('AI Analysis'), view.get('Risk Score')
    result = []
    if ml.get('status') == 'Available':
        result.append(f'INFERRED - AI predicted {text(ml.get("label"))} with {percentage(ml.get("confidence"))} class confidence.')
    else:
        result.append('UNKNOWN - AI classification is unavailable; manual review is required.')
    spf, dkim, dmarc = [view.get(k + ' Analysis') for k in ('SPF', 'DKIM', 'DMARC')]
    result.append(f'REPORTED - SPF: {text(spf.get("reported_result"))}; DKIM: {text(dkim.get("reported_result"))}. Header assertions are not independent verification.')
    result.append('LOCAL CHECK - DKIM: ' + verification(dkim.get('local_verification') or {}) + '; DMARC: ' + verification(dmarc.get('local_assessment') or {}) + '.')
    public = (view.get('Geolocation').get('assessment') or {}).get('observed_public_ips') or []
    if public:
        result.append('OBSERVED - Public relay IP(s): ' + ', '.join(public[:3]) + '.')
    if view.geos:
        result.append('PROVIDER-REPORTED - Relay infrastructure organization: ' + text((view.geos[0].get('result') or {}).get('organization'), 90) + '.')
    origin = view.value('Origin IP') or {}
    result.append('INFERRED - Candidate origin: ' + text(origin.get('candidate_ip')) + '. Insufficient evidence to establish a person\'s location or identity.')
    if score_value(risk) is not None:
        result.append(f'ASSESSMENT - Recorded review priority is {score_value(risk)}/100. This is separate from AI class confidence.')
    return result[:7]


class Bar(Flowable):
    def __init__(self, value, maximum=100, width=150, color=BLUE):
        super().__init__()
        self.width, self.height, self.value, self.maximum, self.color = width, 12, number(value), number(maximum), color

    def draw(self):
        self.canv.setFillColor(colors.HexColor('#e2e9ef'))
        self.canv.roundRect(0, 3, self.width, 6, 3, fill=1, stroke=0)
        if self.value is not None and self.maximum and self.value > 0:
            self.canv.setFillColor(colors.HexColor(self.color))
            filled = min(1, max(0, self.value / self.maximum)) * self.width
            self.canv.roundRect(0, 3, filled, 6, min(3, filled / 2), fill=1, stroke=0)


class MetricCards(Flowable):
    def __init__(self, metrics, severity):
        super().__init__()
        self.width, self.height = CONTENT, 63
        self.metrics, self.severity = metrics, severity

    def draw(self):
        width = (CONTENT - 18) / 4
        for i, (label, value) in enumerate(self.metrics):
            x = i * (width + 6)
            self.canv.setFillColor(colors.HexColor(SEVERITY.get(self.severity, BLUE) if i == 2 else NAVY))
            self.canv.roundRect(x, 4, width, 56, 5, fill=1, stroke=0)
            self.canv.setFillColor(colors.white)
            self.canv.setFont('MT', 8)
            self.canv.drawString(x + 9, 44, label)
            self.canv.setFont('MT-Bold', 13)
            self.canv.drawString(x + 9, 20, text(value, 15))


class RelayStrip(Flowable):
    def __init__(self, names, paragraph):
        super().__init__()
        self.width, self.height = CONTENT, 65
        self.names, self.paragraph = names, paragraph

    def draw(self):
        count = len(self.names)
        width = (CONTENT - (count - 1) * 18) / count
        for i, name in enumerate(self.names):
            x = i * (width + 18)
            self.canv.setFillColor(colors.HexColor('#eaf2f7'))
            self.canv.roundRect(x, 6, width, 55, 4, fill=1, stroke=0)
            p = self.paragraph(name, 45)
            _, height = p.wrap(width - 12, 50)
            p.drawOn(self.canv, x + 6, 55 - height)
            if i < count - 1:
                self.canv.setStrokeColor(colors.HexColor(BLUE))
                start, end = x + width + 3, x + width + 15
                self.canv.line(start, 33, end, 33)
                self.canv.line(end - 4, 37, end, 33)
                self.canv.line(end - 4, 29, end, 33)


class Page:
    def __init__(self, canvas, snapshot, index):
        self.canvas, self.y, self.omitted = canvas, HEIGHT - 133, False
        self.title, question = TITLES[index]
        canvas.setFillColor(colors.HexColor(NAVY))
        canvas.rect(0, HEIGHT - 66, WIDTH, 66, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont('MT-Bold', 15)
        canvas.drawString(MARGIN, HEIGHT - 30, 'MAILTRACE AI')
        canvas.setFont('MT', 8)
        canvas.drawString(MARGIN, HEIGHT - 46, 'FORENSIC INVESTIGATION REPORT')
        canvas.drawRightString(WIDTH - MARGIN, HEIGHT - 30, f'{index + 1:02d} / 10')
        canvas.setFillColor(colors.HexColor(NAVY))
        canvas.setFont('MT-Bold', 19)
        canvas.drawString(MARGIN, HEIGHT - 99, self.title)
        canvas.setFont('MT', 8.5)
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.drawString(MARGIN, HEIGHT - 116, question)
        self.style = ParagraphStyle('body', fontName='MT', fontSize=9, leading=13, textColor=colors.HexColor(NAVY), splitLongWords=True)
        self.small = ParagraphStyle('small', parent=self.style, fontSize=8, leading=11)
        self.white = ParagraphStyle('white', parent=self.small, fontName='MT-Bold', textColor=colors.white)
        self.snapshot = snapshot

    def p(self, value, limit=240, style=None):
        value = text(value, limit)
        # Vera covers Latin (including Portuguese), Greek and Cyrillic. Other
        # glyphs are represented explicitly, with original Unicode kept in JSON.
        font = pdfmetrics.getFont('MT').face.charToGlyph
        value = ''.join(ch if ord(ch) in font else f'[U+{ord(ch):04X}]' for ch in value)
        chosen = style or self.style
        if value in ('PASS', 'FAIL', 'UNKNOWN', 'Unknown', 'PASS (VERIFIED)') and chosen is not self.white:
            chosen = ParagraphStyle('status', parent=chosen, fontName='MT-Bold', textColor=colors.HexColor('#28724f' if value.startswith('PASS') else '#ab2938' if value == 'FAIL' else MUTED))
        return Paragraph(escape(value), chosen)

    def add(self, flowable, gap=7):
        _, height = flowable.wrap(CONTENT, max(0, self.y - 102))
        if height > self.y - 102:
            self.omitted = True
            return False
        flowable.drawOn(self.canvas, MARGIN, self.y - height)
        self.y -= height + gap
        return True

    def body(self, value, limit=460):
        self.add(self.p(value, limit))

    def heading(self, value):
        style = ParagraphStyle('heading', parent=self.style, fontName='MT-Bold', fontSize=10, textColor=colors.HexColor(BLUE))
        self.add(self.p(value, 120, style), 5)

    def table(self, headings, rows, widths, limit=7, cell_limit=110):
        if not rows:
            self.body(NA)
            return
        original_count = len(rows)
        shown = rows[:limit]
        def make(data):
            cells = [[self.p(h, 80, self.white) for h in headings]] + [[v if isinstance(v, Flowable) else self.p(v, cell_limit, self.small) for v in row] for row in data]
            table = Table(cells, colWidths=[CONTENT * w for w in widths])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(NAVY)),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f5f8'), colors.white]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LINEBELOW', (0, 0), (-1, -1), .4, colors.HexColor('#d3dfe7')),
                ('LEFTPADDING', (0, 0), (-1, -1), 7), ('RIGHTPADDING', (0, 0), (-1, -1), 7),
                ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            return table
        while shown:
            table = make(shown)
            if table.wrap(CONTENT, 1000)[1] <= self.y - 128:
                self.add(table)
                if len(shown) < original_count:
                    self.add(self.p(f'Showing {len(shown)} of {original_count} distinct rows; remaining evidence is in JSON.', 160, self.small))
                return
            shown = shown[:-1]
        self.omitted = True

    def kv(self, rows, limit=15):
        self.table(['Field', 'Recorded value'], rows, [.27, .73], limit, 220)

    def finish(self):
        c = self.canvas
        note = 'Additional section details are in JSON; page content budget reached.' if self.omitted else 'Summary only. Long values are shortened; complete evidence remains in JSON.'
        c.setFillColor(colors.HexColor(MUTED))
        c.setFont('MT', 7)
        c.drawString(MARGIN, 82, note)
        c.drawString(MARGIN, 70, 'VERIFIED = local check | REPORTED = assertion | OBSERVED = artifact | INFERRED = interpretation')
        c.setStrokeColor(colors.HexColor('#d3dfe7'))
        c.line(MARGIN, 58, WIDTH - MARGIN, 58)
        c.drawString(MARGIN, 43, 'Confidential - authorized investigation use')
        c.drawRightString(WIDTH - MARGIN, 43, 'Report ' + text(self.snapshot.get('report_id'), 40))
        c.showPage()


def executive(page, view):
    s = view.snapshot
    page.kv([(label, s.get(key)) for label, key in [('Case ID', 'case_id'), ('Report ID', 'report_id'), ('Generated At', 'generated_at'), ('Investigator', 'generated_by')]])
    verdict, risk, ml = view.get('Threat Verdict'), view.get('Risk Score'), view.get('AI Analysis')
    sev = score_severity(view)
    page.add(MetricCards([('Threat verdict', verdict.get('verdict')), ('Risk / 100', score_value(risk)), ('Severity', sev), ('AI confidence', percentage(ml.get('confidence')))], sev))
    page.body('Case status: ' + text(view.get('Case Information').get('status')) + '. Verdict basis: ' + text(verdict.get('source'), 140))
    count = view.get('Executive Summary').get('emails_examined', 0)
    page.body(f'Scope: {count} email(s). Featured email: {text(view.email_id, 50)}. The highest recorded risk is featured consistently; all linked analyses are in JSON.', 270)
    page.heading('Key findings')
    for finding in findings(view):
        page.body('- ' + finding, 270)


def overview(page, view):
    info, sid = view.get('Email Information'), view.value('Sender Identity Analysis') or {}
    def addresses(value):
        return ', '.join(str(x) for x in value) if isinstance(value, list) else value
    return_path = addresses(info.get('return_path') or view.raw.get('return_path'))
    return_domain = sid.get('return_path_domain') or (return_path.rsplit('@', 1)[-1].rstrip('>') if return_path and '@' in return_path else None)
    page.kv([
        ('From', info.get('sender')), ('To', addresses(info.get('recipient'))), ('Reply-To', addresses(info.get('reply_to') or view.raw.get('reply_to'))),
        ('Subject', info.get('subject')), ('Date', info.get('date')), ('Message-ID', info.get('message_id')),
        ('Sender Domain', sid.get('sender_domain')), ('Return-Path Domain', return_domain),
        ('Attachments', len(view.attachments)), ('URLs Found (distinct)', len(view.urls)),
        ('IPs Found (distinct)', len([i for i in view.iocs if i['type'] == 'ip'])),
    ])
    page.heading('Investigation summary')
    page.body(f'The supplied message was examined using the recorded header, content and indicator evidence. The recorded verdict is {text(view.get("Threat Verdict").get("verdict"))}, based on {text(view.get("Threat Verdict").get("source"), 80)}. Available provider and local verification results are summarized separately. Missing checks do not establish safety, and the original evidence remains available for review.', 620)


def ai(page, view):
    ml = view.get('AI Analysis')
    page.kv([('Status', ml.get('status')), ('AI Classification', ml.get('label')), ('Class Confidence', percentage(ml.get('confidence'))), ('Model', ml.get('model_type')), ('Dataset / Version', ml.get('dataset_version') or ml.get('model_version'))])
    page.heading('Class probabilities - model predictions')
    probs = ml.get('probabilities') or {}
    page.table(['Class', 'Probability', 'Visual'], [[k, percentage(probs.get(k)), Bar((number(probs.get(k)) or 0) * 100, width=180)] for k in ('BENIGN', 'PHISHING', 'BEC', 'SPAM')] if probs else [], [.27, .27, .46])
    page.heading('Strongest model indicators')
    indicators = sorted(ml.get('explanation') or [], key=lambda i: abs(number(i.get('logit_contribution', i.get('weight'))) or 0), reverse=True)
    def contribution(item):
        value = number(item.get('logit_contribution', item.get('weight')))
        return f'{"Positive" if value >= 0 else "Negative"} ({value:+.4f})' if value is not None else NA
    page.table(['Term / feature', 'Contribution to predicted class'], [[i.get('term') or i.get('feature'), contribution(i)] for i in indicators], [.55, .45], 6, 90)
    page.body('Positive / negative contributions increase / decrease the model\'s class logit; they are not risk points. Model confidence is not a calibrated probability of harm.', 230)
    limits = ml.get('limitations') or []
    if limits:
        page.body('Model limitations: ' + '; '.join(str(x) for x in limits[:3]), 400)


def authentication(page, view):
    spf, dkim, dmarc = [view.get(k + ' Analysis') for k in ('SPF', 'DKIM', 'DMARC')]
    page.table(['Control', 'Reported result', 'Local verification', 'Alignment*'], [
        ['SPF', spf.get('reported_result'), 'Verification unavailable', alignment(dmarc.get('spf_alignment'))],
        ['DKIM', dkim.get('reported_result'), verification(dkim.get('local_verification') or {}), alignment(dmarc.get('dkim_alignment'))],
        ['DMARC', dmarc.get('reported_result'), verification(dmarc.get('local_assessment') or {}), (dmarc.get('local_assessment') or {}).get('basis')],
    ], [.12, .20, .31, .37], 3, 130)
    page.body('* Alignment from observed domains / header assertions is not independent authentication. DMARC local PASS requires verified aligned DKIM in this upload workflow.', 250)
    page.heading('Evidence and verification boundaries')
    page.body('REPORTED results are assertions in the supplied headers. Uploaded email cannot establish a trusted SMTP peer IP and envelope sender for authoritative SPF verification. Authentication failure alone does not establish malicious intent.', 350)
    page.kv([
        ('SPF policy lookup', (spf.get('dns_policy') or {}).get('status')),
        ('SPF candidate DNS check', (spf.get('candidate_dns_check') or {}).get('status')),
        ('DKIM local check', (dkim.get('local_verification') or {}).get('reason') or (dkim.get('local_verification') or {}).get('limitation')),
        ('DMARC DNS policy', dmarc.get('policy')),
        ('DMARC local basis', (dmarc.get('local_assessment') or {}).get('basis')),
    ])
    if spf.get('candidate_dns_check'):
        page.body('INFERRED - SPF candidate checks use an untrusted relay candidate. Their PASS / FAIL is supplementary and is not authoritative sender verification.', 260)
    page.body('Complete policy records, signatures, alignment evidence and DNS responses are retained in JSON.', 180)


def relay(page, view):
    chain = view.value('Received Path') or []
    page.heading('Observed relay path')
    page.body('Sender / unknown -> supplied relay headers -> recipient. Header order is preserved below; hop numbers do not prove a trusted delivery path.', 220)
    if chain:
        names = ['Origin IP: '+text((view.value('Origin IP') or {}).get('candidate_ip'),40)] + [text(h.get('path_role') or 'Relay',24)+': '+text(h.get('destination_server') or h.get('by'),38) for h in chain[:3]]
        page.add(RelayStrip(names, lambda value, limit: page.p(value, limit, page.small)))
        if len(chain) > 4:
            page.body(f'Path excerpt: 4 of {len(chain)} headers shown; full path is in JSON.')
    geos = {g.get('query'): g.get('result') or {} for g in view.geos}
    rows = []
    for h in chain:
        ip = h.get('parsed_ip') or h.get('ip')
        geo = geos.get(ip) or {}
        stamp = text(h.get('timestamp'), 40)
        try:
            stamp = datetime.fromisoformat(h.get('timestamp')).strftime('%d %b %Y<br/>%H:%M:%S %z')
        except (ValueError, TypeError):
            stamp = escape(stamp)
        protocol_time = Paragraph(escape(text(h.get('protocol'), 18)) + '<br/>' + stamp, page.small)
        rows.append([h.get('hop'), h.get('hostname') or h.get('by'), ip, protocol_time, f'{text(geo.get("asn"))} / {text(geo.get("organization"))}', h.get('confidence')])
    page.table(['Hop', 'Hostname', 'IP', 'Protocol / time', 'ASN / organization', 'Confidence'], rows, [.07, .19, .16, .21, .22, .15], 6, 90)
    page.heading('Meaningful header anomalies')
    anomalies = view.get('Header Forensics').get('anomalies') or []
    if anomalies:
        for a in anomalies[:4]:
            page.body('- ' + text(a.get('description') or a.get('reason') or a.get('type') if isinstance(a, dict) else a, 180))
        if len(anomalies) > 4:
            page.body(f'Showing 4 of {len(anomalies)} anomalies; complete list in JSON.')
    else:
        page.body('No anomalies recorded.' if chain else NA)
    page.body('OBSERVED - Received headers may be forged or affected by server clocks. Full raw headers are in JSON; a relay IP is not a sender identity.', 230)


def iocs(page, view):
    any_rows = False
    detections = {i.get('query'): priority(i) for i in view.intel}
    prioritized = sorted(view.iocs, key=lambda i: detections.get(i['value'], 0), reverse=True)
    ip_values = [i['value'] for i in prioritized if i['type'] == 'ip']
    if ip_values:
        any_rows = True
        from backend.parsers.email_parser import ip_kind
        geo = {g.get('query'): g.get('result') or {} for g in view.geos}
        page.heading('IP addresses - observed')
        page.table(['IP / class', 'ASN / organization', 'Reputation (reported)'], [[str(ip) + ' / ' + ip_kind(ip), f'{text(geo.get(ip, {}).get("asn"))} / {text(geo.get(ip, {}).get("organization"))}', reputation(view, ip)] for ip in ip_values], [.30, .32, .38], 3, 100)
    domains = [i['value'] for i in prioritized if i['type'] == 'domain']
    if domains:
        any_rows = True
        page.heading('Domains')
        def registrar(dom):
            item = next((i for i in view.intel if i.get('query') == dom), {})
            data = (item.get('rdap') or {}).get('result') or {}
            return data.get('registrar') or data.get('organization')
        page.table(['Domain', 'Reputation (reported)', 'Registrar / organization'], [[d, reputation(view, d), registrar(d)] for d in domains], [.33, .42, .25], 3, 95)
    if view.urls:
        any_rows = True
        page.heading('URLs - full addresses remain in JSON')
        urls = sorted(view.urls, key=lambda u: len(u.get('signals') or []), reverse=True)
        page.table(['Shortened URL', 'Local signals'], [[short_url(u.get('original_url') or u.get('url')), ', '.join(str(s.get('type') or s.get('reason')) for s in u.get('signals') or []) or 'No local signals recorded'] for u in urls], [.45, .55], 3, 120)
    if view.attachments:
        any_rows = True
        page.heading('Attachments')
        attachments = sorted(view.attachments, key=lambda a: bool(a.get('flags')), reverse=True)
        page.table(['Filename / type / bytes', 'SHA-256', 'Risk indicators'], [[f'{text(a.get("filename"), 40)} / {text(a.get("content_type"))} / {text(a.get("size"))}', a.get('sha256'), ', '.join(str(f) for f in a.get('flags') or []) or 'No local flags recorded'] for a in attachments], [.34, .43, .23], 2, 110)
    if not any_rows:
        page.body(NA)


def intelligence(page, view):
    page.body('PROVIDER-REPORTED - Positive detections are leads for analyst review. Missing reports and zero detections do not prove safety.', 220)
    statuses = view.get('Threat Intelligence').get('providers') or {}
    page.body('Configuration (not proof of a completed lookup): ' + '; '.join(f'{k}: {text(v, 35)}' for k, v in statuses.items()), 300)
    entries = []
    for item in sorted(view.intel, key=priority, reverse=True):
        for p in item.get('providers') or []:
            if p.get('provider') in ('geoip','ipinfo'):
                continue
            query = short_url(item.get('query')) if item.get('type') == 'url' else item.get('query')
            entries.append((item, p, query))
    entries = unique(entries, lambda e: (e[0].get('type'), e[0].get('query'), e[1].get('provider'), e[1].get('timestamp'), e[1].get('status')))
    coverage = Counter((p.get('provider'), p.get('status')) for _, p, _ in entries if p.get('status') != 'Available')
    # Repeated disabled/not-applicable lookups are coverage gaps, not separate
    # per-indicator findings. Keep the complete responses in the JSON export.
    entries = [e for e in entries if e[1].get('status') not in ('Disabled', 'Not Configured', 'Not Applicable')]
    page.heading('Per-indicator summaries - detections first')
    page.table(['Indicator', 'Provider / status', 'Summary (no engine dump)'], [[q, f'{text(p.get("provider"))} / {text(p.get("status"))}', provider_summary(p)] for _, p, q in entries], [.28, .24, .48], 8, 200)
    page.body('Counts represent individual provider reports; repeated results are deduplicated, not added together. Retrieval timestamps and every engine result remain in JSON.', 240)
    if coverage:
        page.body('Coverage gaps (lookup counts): ' + '; '.join(f'{provider}: {status} ({count})' for (provider, status), count in coverage.items()), 350)
    rdap = Counter((i.get('rdap') or {}).get('status') for i in view.intel if i.get('rdap'))
    dns = Counter((i.get('dns') or {}).get('status') for i in view.intel if isinstance(i.get('dns'), dict))
    page.body('RDAP lookup statuses: ' + (', '.join(f'{text(k)} ({v})' for k, v in rdap.items()) or NA))
    page.body('DNS lookup statuses: ' + (', '.join(f'{text(k)} ({v})' for k, v in dns.items()) or NA))


def origin(page, view):
    from backend.intelligence.providers import ORIGIN_DISCLAIMER
    confidence = view.value('Origin Confidence') or {}
    probable = confidence.get('probable_origin') or {}
    candidate = probable.get('ip') or (view.value('Origin IP') or {}).get('candidate_ip')
    # Older snapshots may store candidate GeoIP only in the Geolocation section.
    old_geo=next((g.get('result') or {} for g in view.geos if g.get('query')==candidate),{})
    probable={**old_geo,**probable}
    def flag(key):
        value = probable.get(key)
        return 'Yes (reported)' if value is True else 'No (reported)' if value is False else 'Unknown / not supplied'
    page.kv([
        ('IP address', candidate),
        ('Country / region / city', ' / '.join(text(probable.get(k)) for k in ('country','region','city'))),
        ('Coordinates (approximate)', f"{text(probable.get('latitude'))}, {text(probable.get('longitude'))}"),
        ('ASN / Organization / ISP', f"{text(probable.get('asn'))} / {text(probable.get('organization'))}"),
        ('Network owner / CIDR', f"{text(probable.get('network_owner'))} / {text(probable.get('network_cidr') or probable.get('asn_cidr'))}"),
        ('Network type / Mail or cloud provider', f"{text(probable.get('network_type') or probable.get('infrastructure_type'))} / {text(probable.get('mail_cloud_provider'))}"),
        ('VPN / Proxy / Tor', ' / '.join(flag(k) for k in ('is_vpn','is_proxy','is_tor'))),
        ('Data source / RDAP cross-check', f"{text(probable.get('data_source'))} / {text((probable.get('rdap_cross_check') or {}).get('status'))}"),
        ('Origin confidence', text(confidence.get('level')) + (' / ' + str(confidence['score']) + ' of 100' if confidence.get('score') is not None else '')),
    ])
    page.body(ORIGIN_DISCLAIMER, 600)
    page.body('Provider names may be inferred from network organization records. Missing privacy flags mean unknown, not a confirmed absence. Field-level sources and all relay locations are retained in JSON.', 300)
    evidence = confidence.get('contributions') or confidence.get('evidence_points') or []
    if evidence:
        page.heading('Origin confidence reasoning (separate from threat risk)')
        # Retain both corroboration and uncertainty in the concise PDF.
        shown = [e for e in evidence if e.get('points',0)<0][:3] + [e for e in evidence if e.get('points',0)>0][:2]
        if not shown:shown=evidence[:2]
        page.table(['Points', 'Reason'], [[e.get('points'), e.get('description') or e.get('reason')] for e in shown], [.12,.88], 5, 170)
        page.body('Full contributions and field-level provenance are available in the JSON evidence export.', 150)


def risk(page, view):
    row = view.get('Risk Score')
    score, sev = score_value(row), score_severity(view)
    page.heading(f'RISK SCORE: {text(score)} / 100     {sev}')
    page.add(Bar(score, width=CONTENT, color=SEVERITY.get(sev, BLUE)))
    contributions = row.get('contributions') or []
    page.heading('Recorded category contributions')
    names = {'authentication': 'Authentication', 'sender_identity': 'Sender identity', 'url': 'URLs', 'attachment': 'Attachments', 'headers': 'Headers', 'intelligence': 'Threat intelligence', 'ai': 'AI analysis', 'correlated_evidence': 'Correlation adjustment', 'model_review': 'Model review adjustment'}
    page.table(['Category', 'Points / maximum', 'Visual'], [[names.get(c.get('category'), c.get('category')), f'{text(c.get("points"))} / {text(c.get("maximum_points"))}', Bar(c.get('points'), c.get('maximum_points'), 170)] for c in contributions], [.40, .22, .38], 10, 100)
    page.body('These are the recorded contributions used for the final score. Diagnostic component scores, when present, are preserved separately in JSON and are not substituted for this calculation.', 300)
    points = [number(c.get('points')) for c in contributions]
    if points and all(p is not None for p in points):
        total = sum(points)
        page.body(f'Contribution sum: {total:.2f}; final recorded score: {text(score)}. ' + ('The total rounds to the recorded score.' if number(score) is not None and round(total) == number(score) else 'The stored breakdown does not reconcile; analyst review is required.'), 270)
    page.body('Formula: ' + text(row.get('formula'), 230), 270)
    thresholds = (row.get('scoring_policy') or {}).get('thresholds')
    if isinstance(thresholds, list) and len(thresholds) == 3:
        a, b, c = thresholds
        page.body(f'Configured thresholds: LOW 0-<{a}; MEDIUM {a}-<{b}; HIGH {b}-<{c}; CRITICAL {c}-100.', 260)
    else:
        page.body('Configured thresholds: Not Available in this snapshot. Historical thresholds are not inferred from current settings.', 230)
    page.body('Risk is review priority, not a probability. Policy adjustments are not additional forensic evidence. Missing evidence does not indicate safety.', 230)


def conclusion(page, view):
    row, verdict = view.get('Risk Score'), view.get('Threat Verdict')
    page.heading('Final assessment')
    page.body(f'The recorded forensic verdict is {text(verdict.get("verdict"))}, based on {text(verdict.get("source"), 90)}. The risk score is {text(score_value(row))}/100 ({score_severity(view)}). AI classification remains a separate model prediction. Header assertions and provider reports have the verification limits described in this report. Sender identity and physical location are not established by relay geolocation.', 630)
    page.heading('Recommended actions')
    actions = ['Preserve the original email, the JSON evidence export and the full SHA-256 hashes.']
    if score_severity(view) in ('HIGH', 'CRITICAL'):
        actions.append('Prioritize analyst review and escalate according to the recorded severity.')
    if any(u.get('signals') for u in view.urls):
        actions.append('Review flagged URLs in an isolated environment before any interaction.')
    if any(a.get('flags') for a in view.attachments):
        actions.append('Examine flagged attachments in a controlled analysis environment.')
    if (view.get('DKIM Analysis').get('local_verification') or {}).get('status') == 'FAIL':
        actions.append('Investigate the local DKIM failure; failure alone does not prove malicious intent.')
    if any(priority(i) > 0 for i in view.intel):
        actions.append('Corroborate provider detections with internal telemetry before blocking indicators.')
    if view.iocs:
        actions.append('Correlate relevant observed indicators with internal mail and network telemetry.')
    for action in actions[:6]:
        page.body('- ' + action)
    page.heading('Evidence integrity')
    s = view.snapshot
    hashes = s.get('evidence_hashes') or []
    page.kv([('Case ID', s.get('case_id')), ('Generated At', s.get('generated_at')), ('Evidence JSON filename', s.get('evidence_export_filename') or f'report-{s.get("report_id")}.json')])
    page.table(['Original evidence SHA-256'], [[h] for h in unique(hashes, lambda h: h)], [1], 3, 100)
    page.body('Full original bytes and collection details, where captured in this snapshot, remain in JSON. Older exports may lack artifacts added by newer collectors; regenerate from preserved evidence to include them.', 300)


def pdf_bytes(snapshot):
    font_dir = Path(reportlab.__file__).parent / 'fonts'
    for name, filename in [('MT', 'Vera.ttf'), ('MT-Bold', 'VeraBd.ttf')]:
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(font_dir / filename)))
    pdfmetrics.registerFontFamily('MT', normal='MT', bold='MT-Bold')
    output = BytesIO()
    canvas = Canvas(output, pagesize=(WIDTH, HEIGHT), pageCompression=1)
    canvas.setTitle(text(snapshot.get('title') or 'Forensic Investigation Report'))
    canvas.setAuthor('MailTrace AI')
    view = View(snapshot)
    for index, render in enumerate([executive, overview, ai, authentication, relay, iocs, intelligence, origin, risk, conclusion]):
        page = Page(canvas, snapshot, index)
        render(page, view)
        page.finish()
    canvas.save()
    return output.getvalue()
