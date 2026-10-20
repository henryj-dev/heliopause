"""Read-only terminal-result courier. Never invokes a network apply/rollback path."""
import argparse
import hashlib
import json
import os
import ssl
import time
import urllib.parse
import urllib.request
from network_executor import atomic, canonical, read_file, read_json


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('terminal delivery redirects forbidden')


def deliver(config, directory):
    settings=config['terminalDelivery']
    if set(settings)!={'url','caFile','certFile','keyFile'}:
        raise ValueError('unsupported terminal delivery configuration')
    url=urllib.parse.urlsplit(settings['url'])
    if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path!='/api/network/execution/terminal':
        raise ValueError('direct HTTPS terminal endpoint required')
    read_file(settings['keyFile'],maximum=16384,secret=True)
    read_file(settings['certFile'],maximum=65536)
    read_file(settings['caFile'],maximum=65536)
    context=ssl.create_default_context(cafile=settings['caFile'])
    context.load_cert_chain(settings['certFile'],settings['keyFile'])
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())
    try:ack=read_json(os.path.join(directory,'terminal-acks.json'))
    except FileNotFoundError:ack={}
    if not isinstance(ack,dict) or len(ack)>1024:raise ValueError('invalid terminal delivery acknowledgments')
    results=read_json(os.path.join(directory,'terminal-results.json'))
    if not isinstance(results,list) or len(results)>1024:raise ValueError('invalid terminal outbox')
    sent=0
    for result in results:
        payload=canonical(result).encode();stamp=hashlib.sha256(payload).hexdigest()
        if stamp in ack:continue
        request=urllib.request.Request(settings['url'],data=payload,headers={'Content-Type':'application/json'},method='POST')
        with opener.open(request,timeout=2) as response:
            body=response.read(4097)
            if len(body)>4096 or json.loads(body).get('settled') is not True:raise ValueError('terminal result not settled')
        ack[stamp]=True
        atomic(os.path.join(directory,'terminal-acks.json'),ack)
        sent+=1
        if sent>=16:break
    return sent


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True);parser.add_argument('--state-dir',required=True);parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    while True:
        try:deliver(read_json(args.config),args.state_dir)
        except Exception:
            if args.once:raise RuntimeError('terminal delivery unavailable; local recovery remains independent') from None
        if args.once:return
        time.sleep(1)


if __name__=='__main__':main()
