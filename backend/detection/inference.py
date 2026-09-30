"""Local artifact-only inference; missing models return explicit unavailability."""
import hashlib,json,re,math
from functools import lru_cache
from pathlib import Path
from backend.config import MODEL_DIR

LABELS=['BENIGN','PHISHING','BEC','SPAM']

class MLService:
    def __init__(self, model_dir=MODEL_DIR):
        self.model=None;self.metadata=None;self.status='Model unavailable'
        try:
            self.metadata=json.loads((model_dir/'metadata.json').read_text())
            kind=self.metadata['model_type']
            if kind=='tfidf_logistic':
                import joblib
                artifact=model_dir/'model.joblib'
                if hashlib.sha256(artifact.read_bytes()).hexdigest()!=self.metadata['model_sha256']: raise ValueError('Artifact checksum mismatch')
                self.model=joblib.load(artifact)
            elif kind in ('cnn','bilstm'):
                import torch
                from backend.detection.networks import CNN, BiLSTM
                self.vocab=json.loads((model_dir/'vocab.json').read_text())
                architecture=self.metadata.get('configuration',{}).get('architecture',{})
                self.model=(CNN if kind=='cnn' else BiLSTM)(len(self.vocab)+2,**architecture)
                self.model.load_state_dict(torch.load(model_dir/'weights.pt',map_location='cpu',weights_only=True));self.model.eval()
            elif kind=='transformer':
                from transformers import AutoTokenizer,AutoModelForSequenceClassification
                self.tokenizer=AutoTokenizer.from_pretrained(model_dir,local_files_only=True)
                self.model=AutoModelForSequenceClassification.from_pretrained(model_dir,local_files_only=True);self.model.eval()
            elif kind=='ensemble':
                self.members=[];self.ensemble_weights=[]
                for member in self.metadata['members']:
                    directory=(model_dir/member['path']).resolve()
                    if not directory.is_relative_to(model_dir.resolve()) or directory==model_dir.resolve():raise ValueError('Invalid member path')
                    meta=json.loads((directory/'metadata.json').read_text())
                    if meta['model_type']=='ensemble':raise ValueError('Nested ensembles are unsupported')
                    if meta['dataset_version']!=self.metadata['dataset_version'] or meta['label_mapping']!=self.metadata['label_mapping']:raise ValueError('Incompatible ensemble member')
                    for name,digest in member['artifact_sha256'].items():
                        file=directory/name
                        if not file.resolve().is_relative_to(directory):raise ValueError('Invalid member artifact')
                        if hashlib.sha256(file.read_bytes()).hexdigest()!=digest:raise ValueError('Ensemble member checksum mismatch')
                    service=MLService(directory)
                    if service.status!='Available':raise ValueError('Ensemble member unavailable')
                    weight=float(member['weight'])
                    if not math.isfinite(weight) or weight<0:raise ValueError('Invalid ensemble weight')
                    self.members.append(service);self.ensemble_weights.append(weight)
                if len(self.members)<2 or abs(sum(self.ensemble_weights)-1)>1e-6:raise ValueError('Invalid ensemble weights')
                self.model=tuple(self.members)
            else:raise ValueError('Unsupported artifact')
            self.status='Available'
        except Exception:self.model=None;self.status='Model unavailable'

    def predict(self,text,explain=True):
        if self.model is None:return {'status':self.status,'label':None,'confidence':None,'probabilities':None}
        kind=self.metadata['model_type'];explanation=[]
        if kind=='tfidf_logistic':
            p=self.model.predict_proba([text])[0]; index=int(p.argmax())
            if explain:
                vector=self.model['tfidf'].transform([text]);coeff=self.model['classifier'].coef_[index]
                terms=self.model['tfidf'].get_feature_names_out()
                contributions=sorted(((terms[j],float(v*coeff[j])) for j,v in zip(vector.indices,vector.data)),key=lambda x:x[1],reverse=True)[:8]
                explanation=[{'term':term,'logit_contribution':value} for term,value in contributions if value>0]
        elif kind=='ensemble':
            import numpy as np
            outputs=[member.predict(text,explain=False) for member in self.members]
            if any(output['status']!='Available' for output in outputs):raise RuntimeError('Ensemble member unavailable')
            p=np.average([[output['probabilities'][label] for label in LABELS] for output in outputs],axis=0,weights=self.ensemble_weights)
        else:
            import torch
            length=int(self.metadata.get('configuration',{}).get('max_length',512))
            if not 8<=length<=512:raise ValueError('Invalid model sequence length')
            with torch.no_grad():
                if kind=='transformer':
                    ids=self.tokenizer.encode(text,add_special_tokens=False)
                    chunks=[ids[i:i+length-2] for i in range(0,max(1,len(ids)),length-2)]
                    encoded=[self.tokenizer.prepare_for_model(c,return_tensors='pt') for c in chunks]
                    p=torch.stack([self.model(**{k:v.reshape(1,-1) for k,v in chunk.items()}).logits.softmax(-1)[0] for chunk in encoded]).mean(0).numpy()
                else:
                    ids=[self.vocab.get(w,1) for w in re.findall(r'\w+',text.lower())]
                    chunks=torch.tensor([(ids[i:i+length]+[0]*length)[:length] for i in range(0,max(1,len(ids)),length)])
                    p=torch.cat([self.model(batch).softmax(-1) for batch in chunks.split(32)]).mean(0).numpy()
        label_id=int(p.argmax())
        return {'status':'Available','label':LABELS[label_id],'label_id':label_id,'confidence':float(p[label_id]),
            'probabilities':{label:float(p[i]) for i,label in enumerate(LABELS)},'model_type':kind,
            'dataset_version':self.metadata['dataset_version'],'explanation':explanation,'limitations':self.metadata.get('limitations',[])}

MODEL_NAMES=('production','baseline','cnn','bilstm','transformer','ensemble')

def artifact_path(name):
    if name not in MODEL_NAMES:raise ValueError('Unknown deployed model')
    return MODEL_DIR if name=='production' else MODEL_DIR.parent/name

def model_catalog():
    result=[]
    for name in MODEL_NAMES:
        try:
            meta=json.loads((artifact_path(name)/'metadata.json').read_text())
            result.append({'name':name,'status':'Artifact present','model_type':meta['model_type'],
                'dataset_version':meta['dataset_version'],'validation_macro_f1':meta.get('validation_macro_f1')})
        except (OSError,ValueError,KeyError):result.append({'name':name,'status':'Model unavailable'})
    return result

@lru_cache(maxsize=1)
def _load_model(path,version):return MLService(Path(path))

def ml_service():
    from backend.database.store import settings
    directory=artifact_path(settings().get('model_name','production'))
    metadata=directory/'metadata.json'
    version=metadata.stat().st_mtime_ns if metadata.exists() else 0
    return _load_model(str(directory),version)

def clear_model_cache():_load_model.cache_clear()
