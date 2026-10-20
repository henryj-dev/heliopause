"""Isolated TLS transport fixture; production Agent owns every writer and watchdog."""
import http.server
import json
import os
import ssl
import sys
import threading
import time
path=sys.argv[1]
lock=threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        with lock:
            with open(path+'/relay-events.jsonl','a') as stream:
                stream.write(json.dumps({'at':time.time(),'path':self.path,'generation':body.get('applied',{}).get('generation'),'state':body.get('applied',{}).get('state')})+'\n')
        wanted=None
        if os.path.exists(path+'/wanted.json'):
            wanted=json.load(open(path+'/wanted.json'))['generation']
        response={'schemaVersion':body.get('schemaVersion'),'generation':wanted,'gate':{'open':True}}
        if os.path.exists(path+'/malformed.json'):response=json.load(open(path+'/malformed.json'))
        data=json.dumps(response).encode()
        refused=os.path.exists(path+'/fail-pending') and body.get('applied',{}).get('state')=='pending'
        self.send_response(503 if refused else 200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_GET(self):
        with open(path+'/artifact-entered','w') as stream:stream.write(str(time.time()))
        if os.path.exists(path+'/hold-artifact'):time.sleep(3)
        filename=path+'/firewall-envelope.json'
        data=open(filename,'rb').read() if os.path.exists(filename) else b''
        self.send_response(200 if data else 503);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
server=http.server.ThreadingHTTPServer(('192.0.2.1',8444),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(path+'/pki/manager.pem',path+'/pki/manager.key')
context.load_verify_locations(path+'/pki/ca.pem');context.verify_mode=ssl.CERT_REQUIRED
server.socket=context.wrap_socket(server.socket,server_side=True)
with open(path+'/relay-ready','w') as stream:stream.write('ready')
server.serve_forever()
