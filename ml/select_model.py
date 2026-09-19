"""Compare compatible artifacts by validation performance; never select on test results."""
import argparse,json,shutil
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('candidates',nargs='+');ap.add_argument('--out',default='ml/artifacts/production');args=ap.parse_args()
rows=[]
for path in map(Path,args.candidates):
    m=json.loads((path/'metadata.json').read_text())
    score=m.get('validation_macro_f1')
    if score is None:score=max(c['validation']['report']['macro avg']['f1-score'] for c in m['validation_candidates'])
    rows.append((score,path,m))
if len({m['dataset_version'] for _,_,m in rows})!=1:raise ValueError('Candidates must use the same dataset and splits')
score,path,metadata=max(rows,key=lambda r:r[0]);out=Path(args.out)
if out.resolve()!=path.resolve():shutil.copytree(path,out,dirs_exist_ok=True)
selection={'selected':str(path),'criterion':'Highest validation macro-F1 on identical grouped splits; test metrics excluded from selection','validation_macro_f1':score,
    'candidates':[{'path':str(p),'model_type':m['model_type'],'validation_macro_f1':s} for s,p,m in rows]}
(out/'selection.json').write_text(json.dumps(selection,indent=2))
metadata['selection']=selection;metadata['validation_macro_f1']=score
(out/'metadata.json').write_text(json.dumps(metadata,indent=2))
print('Selected',path,'validation macro-F1',score)
