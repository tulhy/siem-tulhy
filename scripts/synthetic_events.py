"""Send explicitly synthetic metadata using an existing laboratory agent identity."""
import os
from datetime import timedelta
from agent.config.settings import load
from agent.normalizers import Normalizer
from agent.transport.client import Transport
from shared.events import utcnow

def synthetic(n):
    now = utcnow()
    events = [n.event('auth.failure','synthetic',user='LAB\\test-user',timestamp=now-timedelta(seconds=20-i),raw_event={'synthetic':True}) for i in range(5)]
    process = {'name':'benign-lab.exe','pid':987654,'created_at':now.timestamp()-15,'path':r'C:\Temp\benign-lab.exe'}
    events.append(n.event('process.start','synthetic',process=process,timestamp=now-timedelta(seconds=10),raw_event={'synthetic':True}))
    events.append(n.event('network.connection','synthetic',process=process,network={'remote_ip':'192.0.2.10','remote_port':443,'protocol':'TCP'},raw_event={'synthetic':True}))
    events.append(n.event('file.modified','synthetic',file={'path':r'C:\Lab\monitored.txt'},raw_event={'synthetic':True}))
    return events

if __name__=='__main__':
    config=load()
    if not config.agent_name:
        raise ValueError('Set agent_name to the hostname registered for your separate laboratory agent')
    agent_id=os.environ['SIEM_AGENT_ID']
    transport=Transport(config,agent_id,os.environ['SIEM_AGENT_TOKEN'])
    try:
        events=synthetic(Normalizer(agent_id,config.agent_name))
        response=transport.post('/api/v1/events/batch',{'events':[e.model_dump(mode='json') for e in events]})
        print('Synthetic events acknowledged:',len(response['accepted_ids']))
    finally:
        transport.close()
