"""Snapshot-based JSON and paginated PDF forensic reports."""
import json
from io import BytesIO
from html import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,CondPageBreak
from .store import db,now,uid,clean,DATA,cipher,custody,event
from .forensics import LIMITATIONS

def pdf_bytes(snapshot):
    output=BytesIO();styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='EvidenceText',fontName='Helvetica',fontSize=8,leading=12,spaceAfter=5,wordWrap='CJK'))
    styles['Title'].textColor=colors.HexColor('#12304b');styles['Heading2'].textColor=colors.HexColor('#126b83')
    styles['Heading2'].keepWithNext=True
    document=SimpleDocTemplate(output,pagesize=(595,842),rightMargin=42,leftMargin=42,topMargin=55,bottomMargin=45,
        title=snapshot['title'],author='MailTrace AI',subject='Evidence-backed email investigation')
    story=[Paragraph('MAILTRACE / FORENSIC REPORT',styles['Title']),Paragraph(escape(snapshot['title']),styles['Heading2'])]
    for key in ['report_id','case_id','generated_at','generated_by']:
        story.append(Paragraph(escape(f'{key.replace("_"," ").title()}: {snapshot[key]}'),styles['EvidenceText']))
    def render(value,depth=0):
        if isinstance(value,dict):
            for k,v in value.items():
                if k in {'html_body','model_text','body'}:continue
                label='<b>'+escape(str(k).replace('_',' ').title())+'</b>'
                if isinstance(v,(dict,list)):
                    story.append(Paragraph(label,styles['EvidenceText']));render(v,depth+1)
                else:
                    text=str(v) if v is not None else 'Unknown'
                    excerpt=text[:2500]
                    if len(text)>2500:excerpt+=' [Excerpt; full evidence is included in JSON export.]'
                    story.append(Paragraph(label+': '+escape(excerpt).replace('\n','<br/>'),styles['EvidenceText']))
        elif isinstance(value,list):
            if not value:story.append(Paragraph('Not Available',styles['EvidenceText']))
            for v in value:render(v,depth+1)
        else:
            text=str(value) if value is not None else 'Unknown'
            # Split long values into paragraphs to avoid overheight table rows or unbreakable blocks.
            for start in range(0,max(1,len(text)),1500):
                story.append(Paragraph(escape(text[start:start+1500]).replace('\n','<br/>'),styles['EvidenceText']))
    for number,(name,value) in enumerate(snapshot['sections'].items(),1):
        story.append(CondPageBreak(85));story.append(Spacer(1,10));story.append(Paragraph(f'{number}. '+escape(name),styles['Heading2']));render(value)
    def footer(canvas,doc):
        canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#64748b'))
        canvas.drawString(42,24,'Confidential - authorized investigation use')
        canvas.drawRightString(553,24,f"{snapshot['report_id'][:8]} / Page {doc.page}")
    document.build(story,onFirstPage=footer,onLaterPages=footer)
    return output.getvalue()

def snapshot_case(case,report,user):
    analyses=list(db.email_analysis.find({'email_id':{'$in':case.get('related_emails',[])}}))
    evidences=list(db.evidence.find({'_id':{'$in':case.get('evidence',[])}}))
    def collect(key):return [{'email_id':a['email_id'],'value':a['forensics'].get(key)} for a in analyses]
    sections={
        'Case Information':clean({k:v for k,v in case.items() if k not in {'notes','timeline','evidence','related_iocs','related_emails'}}),
        'Executive Summary':{'emails_examined':len(analyses),'maximum_observed_risk':max((a['risk_score'] for a in analyses),default=None),'status':case['status']},
        'Email Information':[{k:a['forensics'][k] for k in ['subject','sender','recipient','date','message_id']} for a in analyses],
        'Threat Verdict':[{'email_id':a['email_id'],'verdict':a['verdict'],'source':a['verdict_source'],'category':a.get('category'),'category_basis':a.get('category_basis')} for a in analyses],
        'Risk Score':[{'email_id':a['email_id'],'score':a['risk_score'],'contributions':a['contributions'],'formula':a['formula'],'version':a.get('risk_version'),'rules':a.get('correlation_rules',[])} for a in analyses],
        'AI Analysis':[a['ml'] for a in analyses],
        'Header Forensics':[{'email_id':a['email_id'],'anomalies':a['forensics']['anomalies'],'raw_headers':a['forensics']['raw_headers']} for a in analyses],
        'SPF Analysis':[a['forensics']['authentication']['spf'] for a in analyses],
        'DKIM Analysis':[a['forensics']['authentication']['dkim'] for a in analyses],
        'DMARC Analysis':[a['forensics']['authentication']['dmarc'] for a in analyses],
        'Sender Identity Analysis':collect('sender_identity'),
        'Received Path':collect('received_chain'),'Origin IP':collect('origin'),
        'Geolocation':[{'email_id':a['email_id'],'assessment':a.get('geolocation'),'results':[p for i in a['intelligence'] for p in i['providers'] if p['provider']=='geoip']} for a in analyses],
        'Domain Intelligence':[i for a in analyses for i in a['intelligence'] if i['type']=='domain'],
        'URL Analysis':collect('urls'),'Attachment Analysis':collect('attachments'),
        'Threat Intelligence':[{'email_id':a['email_id'],'results':a['intelligence'],'status':a['enrichment_status'],'providers':a['provider_status']} for a in analyses],
        'Infrastructure Correlation':[a['graph'] for a in analyses],
        'Campaign Correlation':{'suggestions':[a['related_emails'] for a in analyses],
            'reviewed_campaigns':clean(list(db.campaigns.find({'email_ids':{'$in':case.get('related_emails',[])}})))},
        'Timeline':sorted([e for a in analyses for e in a['timeline']]+clean(case.get('timeline',[])),key=lambda e:e['timestamp']),
        'Evidence':clean(evidences),'Chain of Custody':[clean(e['processing_history']) for e in evidences],
        'Analyst Notes':clean(case.get('notes',[])),
        'Findings':[a['signals'] for a in analyses],'Limitations':LIMITATIONS,
    }
    return {'report_id':report['_id'],'case_id':case['_id'],'title':report['title'],
        'generated_at':now().isoformat(),'generated_by':user['email'],'sections':sections,
        'evidence_hashes':[e['sha256'] for e in evidences],
        'raw_header_appendix':collect('raw_headers')}

def build_report(job):
    report=db.reports.find_one({'_id':job['report_id']});case=db.cases.find_one({'_id':report['case_id']});user=db.users.find_one({'_id':job['user_id']})
    if not case or not user:raise ValueError('Report case or author is unavailable')
    snapshot=snapshot_case(case,report,user)
    directory=DATA/'reports';directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    for format,content in [('json',json.dumps(snapshot,ensure_ascii=False,indent=2).encode()),('pdf',pdf_bytes(snapshot))]:
        path=directory/(report['_id']+'.'+format+'.enc')
        with path.open('wb') as f:f.write(cipher().encrypt(content))
        path.chmod(0o600)
    db.reports.update_one({'_id':report['_id']},{'$set':{'status':'Completed','completed_at':now(),'evidence_hashes':snapshot['evidence_hashes']}})
    db.jobs.update_one({'_id':job['_id']},{'$set':{'status':'Completed','updated_at':now()},'$unset':{'lease_until':''}})
    for evidence_id in case.get('evidence',[]):custody(evidence_id,'Report generated',job['user_id'],{'report_id':report['_id']})
    event('Report generated',user,'report',report['_id'],{'case_id':case['_id']})
