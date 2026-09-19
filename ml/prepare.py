"""Canonical corpus builder with explicit label mappings and grouped holdouts."""
import argparse
import csv
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from app.platform.forensics import parse
from sklearn.model_selection import StratifiedGroupKFold

LABELS={'BENIGN':0,'PHISHING':1,'BEC':2,'SPAM':3}
csv.field_size_limit(20_000_000)

def canonical(data,label,source,subset,original_label,source_file):
    text=(data.get('subject','')+'\n'+data.get('body','')).strip()
    normalized=re.sub(r'\s+',' ',text).casefold()
    digest=hashlib.sha256(normalized.encode()).hexdigest()
    return {'id':digest,'subject':data.get('subject',''),'body':data.get('body',''),'model_text':text,
        'sender':data.get('sender',''),'recipient':data.get('recipient',data.get('receiver','')),
        'reply_to':data.get('reply_to',[]),'date':data.get('date',''),'message_id':data.get('message_id',''),
        'headers':data.get('headers',{}),'html_body':data.get('html_body',''),'urls':data.get('urls',[]),
        'attachment_names':[a['filename'] for a in data.get('attachments',[])],
        'attachment_types':[a['mime_type'] for a in data.get('attachments',[])],
        'original_label':original_label,'label':label,'label_id':LABELS[label],'source_dataset':source,
        'source_subset':subset,'source_file':source_file,'content_hash':digest,
        'synthetic':source=='BEC-2','in_reply_to':data.get('in_reply_to',''),'references':data.get('references','')}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--root',default='MailTrace-AI Dataset'); ap.add_argument('--out',default='ml/artifacts/dataset')
    ap.add_argument('--enron-limit',type=int,default=10000,help='Seeded reservoir sample; 0 includes all Enron files')
    args=ap.parse_args(); root=Path(args.root); out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    rows=[]; counts=Counter(); files=Counter(); quarantine=[]; rng=random.Random(42)
    def add(data,label,source,subset,original,path):
        row=canonical(data,label,source,subset,original,str(path.relative_to(root)))
        if len(row['model_text'].strip())<10: counts['empty_or_short']+=1; return
        rows.append(row)
    for folder,label,source in [('benign','BENIGN','SpamAssassin'),('spam','SPAM','SpamAssassin'),('ENRON','BENIGN','Enron')]:
        directory=root/folder
        if not directory.exists(): counts['missing_'+folder]+=1; continue
        selected=[]; n=0
        for path in sorted(directory.rglob('*')):
            if not path.is_file() or path.name.startswith('.') or path.name.lower() in {'cmds','readme'}:continue
            files[source]+=1; n+=1
            if folder=='ENRON' and args.enron_limit:
                if len(selected)<args.enron_limit:selected.append(path)
                else:
                    j=rng.randrange(n)
                    if j<args.enron_limit:selected[j]=path
            else:selected.append(path)
        for path in selected:
            try:
                add(parse(path.read_bytes()),label,source,path.parent.name,label,path)
            except Exception: counts['parse_failure']+=1
    for path in sorted(root.rglob('*.csv')):
        with path.open(encoding='utf-8-sig',errors='replace',newline='') as f:
            for index,row in enumerate(csv.DictReader(f)):
                data={k.lower():v for k,v in row.items() if k}; files[path.stem]+=1
                label=None
                if path.name=='BEC-2-human.csv':
                    original=data.get('human',''); source='BEC-2'
                    if original=='positive':label='BEC'
                elif path.name=='Nazario.csv':
                    original=data.get('label',''); source='Nazario'
                    if original=='1':label='PHISHING'
                    elif original=='0':label='BENIGN'
                elif path.name=='CEAS_08.csv':
                    original=data.get('label',''); source='CEAS-08'
                    # Binary spam/phishing labels cannot support a defensible 4-class positive mapping.
                    if original=='0':label='BENIGN'
                else:
                    original=data.get('label','').upper(); source=path.stem
                    if original in LABELS:label=original
                if label is None:
                    counts['ambiguous_label']+=1; quarantine.append({'file':str(path.relative_to(root)),'row':index+2,'label':original}); continue
                add(data,label,source,path.stem,original,path)
    # Exact deduplication removes cross-label conflicts instead of choosing a label.
    unique={}; conflict=set()
    for row in rows:
        key=row['content_hash']
        if key in unique:
            counts['exact_duplicates']+=1
            if unique[key]['label']!=row['label']:conflict.add(key)
        else:unique[key]=row
    rows=[r for k,r in unique.items() if k not in conflict]; counts['conflicting_content_hashes']=len(conflict)
    parent=list(range(len(rows)))
    def find(i):
        while parent[i]!=i:parent[i]=parent[parent[i]]; i=parent[i]
        return i
    def union(a,b):parent[find(a)]=find(b)
    identifiers={}; subjects={}; bands=defaultdict(list); signatures=[]
    for i,row in enumerate(rows):
        ids=re.findall(r'<[^>]+>',row['message_id']+' '+row['in_reply_to']+' '+row['references'])
        for ident in ids:
            if ident in identifiers:union(i,identifiers[ident])
            else:identifiers[ident]=i
        subject=re.sub(r'^(?:(?:re|fw|fwd):\s*)+','',row['subject'].lower()).strip()
        if len(subject)>12:
            if subject in subjects:union(i,subjects[subject])
            else:subjects[subject]=i
        # 64-bit SimHash, four LSH bands. All pairs with <=3 changed bits share a band.
        words=re.findall(r'\w+',row['model_text'].lower())[:3000]
        shingles={' '.join(words[j:j+3]) for j in range(max(1,len(words)-2))}
        accum=[0]*64
        for shingle in shingles:
            h=int.from_bytes(hashlib.blake2b(shingle.encode(),digest_size=8).digest(),'big')
            for bit in range(64):accum[bit]+=1 if h>>bit&1 else -1
        signature=sum(1<<bit for bit,n in enumerate(accum) if n>=0); signatures.append(signature)
        candidates=set()
        for band in range(4): candidates.update(bands[(band,(signature>>(band*16))&65535)])
        for j in candidates:
            if (signature^signatures[j]).bit_count()<=3:union(i,j); counts['near_duplicate_links']+=1
        for band in range(4):bands[(band,(signature>>(band*16))&65535)].append(i)
    groups=[find(i) for i in range(len(rows))]; labels=[r['label_id'] for r in rows]
    print('Before splitting:',dict(Counter(labels)),'group sizes:',Counter(groups).most_common(5),flush=True)
    # Twenty grouped stratified folds approximate 70/15/15 without breaking groups.
    splitter=StratifiedGroupKFold(n_splits=20,shuffle=True,random_state=42)
    assignment={}
    for fold,(_,indices) in enumerate(splitter.split(rows,labels,groups)):
        for i in indices:assignment[int(i)]='test' if fold<3 else 'validation' if fold<6 else 'train'
    distribution={}; manifest_hash=hashlib.sha256()
    for split in ['train','validation','test']:
        selected=[{**r,'group_id':str(groups[i]),'split':split} for i,r in enumerate(rows) if assignment[i]==split]
        distribution[split]=dict(Counter(r['label'] for r in selected))
        if set(distribution[split])!=set(LABELS):raise ValueError(f'{split} lacks a class: {distribution[split]}; inspect available labels/groups')
        with (out/(split+'.jsonl')).open('w') as f:
            for row in selected:
                line=json.dumps(row,ensure_ascii=True)+'\n'; f.write(line); manifest_hash.update(line.encode())
    report={'dataset_version':manifest_hash.hexdigest(),'seed':42,'target_split':[.70,.15,.15],
        'source_files_or_rows':dict(files),'accepted':len(rows),'counts':dict(counts),'class_distribution':distribution,
        'enron_limit':args.enron_limit,'groups':len(set(groups)),
        'limitations':['BEC-2 is synthetic, human-reviewed data; generalization to real BEC is unproven.',
            'CEAS positive rows excluded: binary labels conflate spam/phishing.',
            'Enron sampled by seeded reservoir unless --enron-limit 0.',
            'Near-duplicate detection is approximate SimHash <=3 bits, not a guarantee against semantic leakage.',
            'No campaign identifiers supplied; normalized subjects and message references group possible threads.'],
        'sources':{'BEC-2':'https://github.com/r-dube/bec','SpamAssassin':'https://spamassassin.apache.org/old/publiccorpus/',
                   'Enron':'https://www.cs.cmu.edu/~enron/','Nazario':'https://monkey.org/~jose/phishing/'}}
    (out/'manifest.json').write_text(json.dumps(report,indent=2)); (out/'quarantine.json').write_text(json.dumps(quarantine,indent=2))
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
