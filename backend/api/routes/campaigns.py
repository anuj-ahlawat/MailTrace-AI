"""Campaigns."""
import re
from fastapi import APIRouter, Depends, HTTPException, Query
from backend.database.store import db, now, uid, event
from backend.core.security import current_user, senior
from backend.schemas.requests import CampaignCreate
from backend.api.dependencies import get, output, collection_page

router = APIRouter()

@router.get('/campaigns')
def campaigns(skip:int=Query(0,ge=0),limit:int=Query(25,ge=1,le=100),q:str=Query('',max_length=250),user=Depends(current_user)):
    query={'$or':[{key:{'$regex':re.escape(q),'$options':'i'}} for key in ('title','reason','shared_indicators')]} if q else {}
    return collection_page('campaigns',user,skip,limit,query)


@router.post('/campaigns')
def campaign(data:CampaignCreate,user=Depends(senior)):
    records=[get('email_analysis',eid) for eid in set(data.email_ids)]
    if len(records)<2:raise HTTPException(422,'At least two distinct emails required')
    shared=set(records[0]['ioc_values'])
    for row in records[1:]:shared &= set(row['ioc_values'])
    row={'_id':uid(),'title':data.title,'email_ids':list(set(data.email_ids)),'shared_indicators':sorted(shared),
        'reason':data.reason,'created_by':user['_id'],'created_at':now(),'severity':max(records,key=lambda a:a['risk_score'])['severity'],
        'assessment':'Analyst-associated campaign; shared infrastructure is not proof of common authorship'}
    db.campaigns.insert_one(row);event('Campaign correlated',user,'campaign',row['_id'],{'reason':data.reason});return output(row,user)


@router.get('/campaigns/{campaign_id}/graph')
def campaign_graph(campaign_id:str,user=Depends(current_user)):
    row=get('campaigns',campaign_id);nodes={};edges={}
    for a in db.email_analysis.find({'email_id':{'$in':row['email_ids']}}):
        for n in a['graph']['nodes']:nodes[n['id']]=n
        for e in a['graph']['edges']:edges[e['id']]=e
    return output({'nodes':list(nodes.values()),'edges':list(edges.values())},user)

