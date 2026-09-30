"""Shared held-out classification metrics for all training families."""
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

LABELS=['BENIGN','PHISHING','BEC','SPAM']
def metrics(y,p):
    return {'accuracy':accuracy_score(y,p),'report':classification_report(y,p,labels=list(range(4)),target_names=LABELS,output_dict=True,zero_division=0),
            'confusion_matrix':confusion_matrix(y,p,labels=list(range(4))).tolist()}
