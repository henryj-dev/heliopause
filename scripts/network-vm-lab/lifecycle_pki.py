#!/usr/bin/env python3
"""Create isolated 3-day lifecycle-test PKI on a marked peer; no operational PKI.

Preparation creates a new test CA, not a claim of deployed CA continuity. Activation and
leaf pin changes are explicit fixture steps, separately measured against production mTLS.
Private bytes never appear in output. This does not alter any journal or network resource.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,'/source/agent')
import network_executor as n
from guest_fixture import guard,command,protected

BASE=Path('/var/lib/heliopause-lifecycle-lab')
LABELS={'manager','gateway','gateway-next','gateway-retry','alice','bob','wrong-cn','wrong-eku','wrong-ca'}


def metadata(path):
    # Binary DER never passes a text decoder or a log.
    import subprocess
    der=subprocess.run(['openssl','x509','-in',str(path),'-outform','DER'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5).stdout
    return {'certificateSha256':hashlib.sha256(der).hexdigest(),
            'publicCertificateSha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'subject':command('openssl','x509','-in',str(path),'-noout','-subject'),
            'validity':command('openssl','x509','-in',str(path),'-noout','-dates').splitlines(),
            'extendedKeyUsage':command('openssl','x509','-in',str(path),'-noout','-ext','extendedKeyUsage')}


def prepare():
    BASE.mkdir(mode=0o700)
    directory=BASE/'pki';directory.mkdir(mode=0o700)
    command('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
            '-keyout',str(directory/'ca.key'),'-out',str(directory/'ca.pem'),'-days','3','-subj','/CN=lifecycle-disposable-ca')
    (directory/'ca.key').chmod(0o600)
    command('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
            '-keyout',str(directory/'wrong-root.key'),'-out',str(directory/'wrong-ca-root.pem'),'-days','3','-subj','/CN=wrong-disposable-ca')
    (directory/'wrong-root.key').chmod(0o600)
    for label in sorted(LABELS):
        key=directory/(label+'.key');csr=directory/(label+'.csr');cert=directory/(label+'.pem')
        subject='manager' if label=='manager' else label if label in {'alice','bob'} else 'intruder' if label=='wrong-cn' else 'gateway'
        command('openssl','req','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN='+subject)
        key.chmod(0o600)
        extension=directory/(label+'.ext')
        protected(extension,'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,'+('serverAuth\nsubjectAltName=IP:192.0.2.1\n' if label=='manager' else 'serverAuth\n' if label=='wrong-eku' else 'clientAuth\n'))
        authority='wrong-root' if label=='wrong-ca' else 'ca'
        command('openssl','x509','-req','-in',str(csr),'-CA',str(directory/('wrong-ca-root.pem' if authority=='wrong-root' else 'ca.pem')),
                '-CAkey',str(directory/(authority+'.key')),'-CAcreateserial','-out',str(cert),'-days','3','-extfile',str(extension))
        cert.chmod(0o600)
    for path in directory.iterdir():path.chmod(0o600)
    result={label:metadata(directory/(label+'.pem')) for label in sorted(LABELS)}
    n.atomic(str(BASE/'pki-prepared.json'),{'newIsolatedCa':True,'labels':result})
    return {'newIsolatedCa':True,'labels':result}


def main():
    p=argparse.ArgumentParser();p.add_argument('--nonce',required=True);p.add_argument('--action',choices=['prepare','metadata'],required=True);a=p.parse_args()
    guard('peer',a.nonce)
    if a.action=='prepare':result=prepare()
    else:result={label:metadata(BASE/'pki'/(label+'.pem')) for label in sorted(LABELS)}
    print(json.dumps(result,allow_nan=False))


if __name__=='__main__':main()
