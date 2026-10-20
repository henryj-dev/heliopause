"""Lab client: real direct mTLS, no alternate approval/settlement implementation."""
import json
import ssl
import sys
import urllib.error
import urllib.request
path,identity,action=sys.argv[1:4]
context=ssl.create_default_context(cafile=path+'/pki/ca.pem')
context.load_cert_chain(path+'/pki/'+identity+'.pem',path+'/pki/'+identity+'.key')
body=json.load(open(sys.argv[4])) if len(sys.argv)>4 else None
request=urllib.request.Request('https://192.0.2.1:8443/api/network/execution/'+action,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
try:
    with opener.open(request,timeout=3) as response:print(json.dumps({'status':response.status,'body':json.load(response)}))
except urllib.error.HTTPError as error:print(json.dumps({'status':error.code,'body':json.load(error)}))
