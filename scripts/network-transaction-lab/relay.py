"""Isolated TLS transport fixture; production Agent owns every writer and watchdog."""
import http.server
import json
import os
import ssl
import sys
import threading
import time
from observation_fixture import ObservationTransport, handle_observation

lock=threading.Lock()
class FixtureServer(http.server.ThreadingHTTPServer):
    observation_transport=None
    def server_close(self):
        super().server_close()
        if self.observation_transport is not None:
            self.observation_transport.close()
            self.observation_transport=None

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args): pass
    def do_POST(self):
        if self.server.observation_transport is not None and handle_observation(self,self.server.observation_transport):return
        path=self.server.fixture_root
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
        if self.server.observation_transport is not None and handle_observation(self,self.server.observation_transport):return
        path=self.server.fixture_root
        with open(path+'/artifact-entered','w') as stream:stream.write(str(time.time()))
        if os.path.exists(path+'/hold-artifact'):time.sleep(3)
        filename=path+'/firewall-envelope.json'
        data=open(filename,'rb').read() if os.path.exists(filename) else b''
        self.send_response(200 if data else 503);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
def create_server(path,host='192.0.2.1',port=8444):
    with open(path+'/config.json') as stream:cfg=json.load(stream)
    enabled=cfg.get('lifecycleObservationTransport',False)
    if type(enabled) is not bool:raise ValueError('explicit boolean observation transport required')
    if enabled and cfg.get('identity')!={'source':'lab','host':'gateway','nodeId':'gateway'}:raise ValueError('fixed disposable observation identity required')
    transport=ObservationTransport(path) if enabled else None
    try:server=FixtureServer((host,port),Handler)
    except BaseException:
        if transport is not None:transport.close()
        raise
    server.fixture_root=path;server.observation_transport=transport
    try:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(path+'/pki/manager.pem',path+'/pki/manager.key')
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(path+'/pki/ca.pem');context.verify_mode=ssl.CERT_REQUIRED
        server.socket=context.wrap_socket(server.socket,server_side=True)
    except BaseException:
        server.server_close()
        raise
    return server


def main():
    path=sys.argv[1]
    server=create_server(path)
    with open(path+'/relay-ready','w') as stream:stream.write('ready')
    try:server.serve_forever()
    finally:server.server_close()


if __name__=='__main__':main()
