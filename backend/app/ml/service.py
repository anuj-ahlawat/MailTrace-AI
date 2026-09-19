"""Local artifact-only inference; missing models return explicit unavailability."""
import hashlib,json,re,sys
from functools import lru_cache
from pathlib import Path
from app.platform.store import MODEL_DIR,ROOT,settings

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
                sys.path.insert(0,str(ROOT/'ml'));from models.networks import CNN,BiLSTM
                self.vocab=json.loads((model_dir/'vocab.json').read_text())
                self.model=(CNN if kind=='cnn' else BiLSTM)(len(self.vocab)+2)
                self.model.load_state_dict(torch.load(model_dir/'weights.pt',map_location='cpu',weights_only=True));self.model.eval()
            elif kind=='transformer':
                from transformers import AutoTokenizer,AutoModelForSequenceClassification
                self.tokenizer=AutoTokenizer.from_pretrained(model_dir,local_files_only=True)
                self.model=AutoModelForSequenceClassification.from_pretrained(model_dir,local_files_only=True);self.model.eval()
            else:raise ValueError('Unsupported artifact')
            self.status='Available'
        except Exception:self.model=None;self.status='Model unavailable'

    def predict(self,text):
        if self.model is None:return {'status':self.status,'label':None,'confidence':None,'probabilities':None}
        kind=self.metadata['model_type'];explanation=[]
        if kind=='tfidf_logistic':
            p=self.model.predict_proba([text])[0]; index=int(p.argmax())
            vector=self.model['tfidf'].transform([text]);coeff=self.model['classifier'].coef_[index]
            terms=self.model['tfidf'].get_feature_names_out()
            contributions=sorted(((terms[j],float(v*coeff[j])) for j,v in zip(vector.indices,vector.data)),key=lambda x:x[1],reverse=True)[:8]
            explanation=[{'term':term,'logit_contribution':value} for term,value in contributions if value>0]
        else:
            import torch
            with torch.no_grad():
                if kind=='transformer':
                    ids=self.tokenizer.encode(text,add_special_tokens=False)
                    chunks=[ids[i:i+510] for i in range(0,max(1,len(ids)),510)]
                    encoded=[self.tokenizer.prepare_for_model(c,return_tensors='pt') for c in chunks]
                    p=torch.stack([self.model(**{k:v.reshape(1,-1) for k,v in chunk.items()}).logits.softmax(-1)[0] for chunk in encoded]).mean(0).numpy()
                else:
                    ids=[self.vocab.get(w,1) for w in re.findall(r'\w+',text.lower())]
                    chunks=torch.tensor([(ids[i:i+512]+[0]*512)[:512] for i in range(0,max(1,len(ids)),512)])
                    p=torch.cat([self.model(batch).softmax(-1) for batch in chunks.split(32)]).mean(0).numpy()
        label_id=int(p.argmax())
        return {'status':'Available','label':LABELS[label_id],'label_id':label_id,'confidence':float(p[label_id]),
            'probabilities':{label:float(p[i]) for i,label in enumerate(LABELS)},'model_type':kind,
            'dataset_version':self.metadata['dataset_version'],'explanation':explanation,'limitations':self.metadata.get('limitations',[])}

MODEL_NAMES=('production','baseline','cnn','bilstm','transformer')

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
    directory=artifact_path(settings().get('model_name','production'))
    metadata=directory/'metadata.json'
    version=metadata.stat().st_mtime_ns if metadata.exists() else 0
    return _load_model(str(directory),version)

def clear_model_cache():_load_model.cache_clear()
