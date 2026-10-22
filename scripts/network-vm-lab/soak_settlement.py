"""Pure settlement projections and fail-closed baseline checks, never a writer.

The caller supplies the production canonical digest. Projections omit authorization
payloads, profiles and proof bodies; result hashes commit to their exact parsed content.
"""
import re

TERMINAL = {'confirmed', 'rolled-back', 'cancelled-before-accept'}
FIELDS = ('schemaVersion','domain','transactionId','fenceId','journalId','authorizationHash','artifactHash','registryRevision','state','sequence','stateHash')


def need(value, reason):
    if not value:
        raise ValueError('baseline settlement: '+reason)


def hex_value(value, size=64):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{'+str(size)+'}',value) is not None


def result_view(value, digest):
    if not isinstance(value,dict):
        return None
    return {**{key:value.get(key) for key in FIELDS},'targetHash':digest(value.get('target')),'resultHash':digest(value)}


def agent_view(rows, outbox, acknowledgments, digest):
    records=[]
    for tx,row in rows.items():
        a=row['authorization']
        records.append({'transactionId':tx,'targetHash':digest(a['target']),'journalId':a['journalId'],
                        'authorizationHash':digest(a),'artifactHash':a['artifactHash'],'registryRevision':a['registryRevision'],
                        'state':row['state'],'result':result_view(row.get('terminalResult'),digest),
                        'cancellationResponse':result_view(row.get('cancellationResponse'),digest)})
    return {'records':records,'outbox':[result_view(value,digest) for value in outbox] if isinstance(outbox,list) else None,'acknowledgments':acknowledgments}


def manager_view(records, digest):
    return [{**{key:row.get(key) for key in ('sequence','transactionId','target','journalId','authorizationHash','artifactHash','registryRevision','state','resultHash','cancellationResponseHash')},
             'result':result_view(row.get('result'),digest),'cancellationResponse':result_view(row.get('cancellationResponse'),digest)} for row in records]


def indexed(records):
    need(isinstance(records,list),'record list required')
    ids=[row.get('transactionId') if isinstance(row,dict) else None for row in records]
    need(all(hex_value(tx,32) for tx in ids) and len(ids)==len(set(ids)),'invalid or duplicate transaction')
    return dict(zip(ids,records))


def require_settled(gateway, peer, expected_tx, digest):
    """Require the initial sample to be settled too; unchanged hashes are insufficient."""
    identity=gateway['targetBinding']['identity'];journal=gateway['journalId'];target_hash=digest(identity)
    local=gateway.get('settlement');remote=peer.get('settlement')
    need(isinstance(local,dict),'Agent settlement inventory required')
    agent=indexed(local.get('records'));manager=indexed(remote)
    need(set(agent)==set(manager)==set(gateway['transactions']) and expected_tx in agent,'Agent/Manager transaction set mismatch')
    count=len(agent)
    need(type(gateway['acceptedSequence']) is int and type(gateway['terminalSequence']) is int and gateway['acceptedSequence']==gateway['terminalSequence']==count,'terminal counters mismatch')
    need(type(peer['ledger'].get('records')) is int and peer['ledger']['records']==count and type(peer['ledger'].get('nextSequence')) is int and peer['ledger']['nextSequence']==count+1,'Manager counters mismatch')
    need(sorted(row['sequence'] for row in manager.values() if type(row['sequence']) is int)==list(range(1,count+1)),'Manager sequence mismatch')
    outbox=local.get('outbox');acks=local.get('acknowledgments')
    need(isinstance(outbox,list) and len(outbox)==count,'outbox coverage mismatch')
    published=indexed(outbox)
    need(set(published)==set(agent),'outbox transaction set mismatch')
    need(isinstance(acks,dict) and all(hex_value(key) and value is True for key,value in acks.items()),'ack values must be exact true')
    allowed_acks=set();sequences=[]
    for tx,row in agent.items():
        result=row.get('result');record=manager[tx]
        need(row['state']==gateway['transactions'][tx]['state'] and row['authorizationHash']==gateway['transactions'][tx]['authorizationHash'],'Agent projection mismatch')
        need(row['state'] in TERMINAL and isinstance(result,dict),'nonterminal or missing terminal result')
        need(record['state']=='settled','Manager record is not settled')
        need(row['journalId']==record['journalId']==journal and row['targetHash']==digest(record['target'])==target_hash,'target/journal mismatch')
        need(all(digest(row[key])==digest(record[key]) for key in ('authorizationHash','artifactHash','registryRevision')),'authorization binding mismatch')
        need(hex_value(row['authorizationHash']) and hex_value(row['artifactHash']) and type(row['registryRevision']) is int and 1<=row['registryRevision']<=2**53-1,'invalid authority commitment')
        need(result['transactionId']==result['fenceId']==tx and result['journalId']==journal and result['targetHash']==target_hash,'result identity mismatch')
        need(all(digest(result[key])==digest(row[key]) for key in ('authorizationHash','artifactHash','registryRevision','state')),'terminal result binding mismatch')
        need(type(result['sequence']) is int and 1<=result['sequence']<=1024,'invalid result sequence')
        schema=2 if row['state']=='cancelled-before-accept' else 1
        domain='heliopause-network-cancellation-mtls-v1' if schema==2 else 'heliopause-network-terminal-mtls-v1'
        need(type(result['schemaVersion']) is int and result['schemaVersion']==schema and result['domain']==domain,'invalid terminal result domain')
        need(hex_value(result['resultHash']) and hex_value(result['stateHash']),'invalid terminal hash')
        need(digest(record['result'])==digest(result) and record['resultHash']==result['resultHash'] and digest(published[tx])==digest(result),'exact Manager/result/outbox mismatch')
        need(acks.get(result['resultHash']) is True,'terminal result not acknowledged')
        allowed_acks.add(result['resultHash']);sequences.append(result['sequence'])
        # An accepted cancellation response may have been acked before the final undo.
        # It is no longer in the terminal outbox, but its exact old receipt remains valid.
        response=row.get('cancellationResponse');manager_response=record.get('cancellationResponse')
        if response is not None:
            need(isinstance(response,dict) and response['transactionId']==response['fenceId']==tx and response['journalId']==journal and response['targetHash']==target_hash,'cancellation response identity mismatch')
            need(all(digest(response[key])==digest(row[key]) for key in ('authorizationHash','artifactHash','registryRevision')),'cancellation response binding mismatch')
            need(type(response['schemaVersion']) is int and response['schemaVersion']==2 and response['domain']=='heliopause-network-cancellation-mtls-v1' and response['state']=='cancellation-rejected' and type(response['sequence']) is int and 1<=response['sequence']<=1024 and hex_value(response['stateHash']) and hex_value(response['resultHash']),'invalid cancellation response')
        if manager_response is not None:
            need(response is not None and digest(manager_response)==digest(response) and record.get('cancellationResponseHash')==response['resultHash'],'cancellation response mismatch')
            allowed_acks.add(response['resultHash'])
        elif response is not None:
            need(response['resultHash'] not in acks,'response ack has no Manager record')
    need(sorted(sequences)==list(range(1,count+1)),'terminal sequence coverage mismatch')
    need(set(acks)<=allowed_acks,'unknown or foreign acknowledgment')
