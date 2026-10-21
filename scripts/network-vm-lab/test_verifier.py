"""Execute generated gateway probe with stubbed command/file boundaries; never touch host networking."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import types
import unittest
from unittest.mock import patch
import verifier

DEV='hp'+'a'*12
MARKER={'role':'gateway','nonce':'b'*32}
BOOT='11111111-1111-1111-1111-111111111111'
OP={'interfaceName':DEV,'address':'192.0.2.129/32','mtu':1400,'routes':['192.0.2.130/32','198.51.100.6/32'],'peers':[{'publicKey':'fixture-peer'}]}


class Collector(unittest.TestCase):
    def setUp(self):
        for module,name in [(subprocess,'Popen'),(socket,'socket')]:
            guard=patch.object(module,name,side_effect=AssertionError('escaped collector unit boundary'));guard.start();self.addCleanup(guard.stop)
    def collect(self):
        calls=[]
        def command(args,**kwargs):
            calls.append(args)
            if args==['wg','show',DEV,'latest-handshakes']:return types.SimpleNamespace(returncode=0,stdout=b'fixture-peer\t200\n')
            if args[:2]!=['ip','-j']:raise AssertionError('unexpected gateway command')
            if args[2:]==['-d','link','show','dev',DEV]:value=[{'mtu':1400,'flags':['UP'],'linkinfo':{'info_kind':'wireguard'}}]
            elif args[2:]==['address','show','dev',DEV]:value=[{'addr_info':[{'local':'192.0.2.129','prefixlen':32}]}]
            elif args[2:]==['-4','route','show','table','main']:value=[{'dst':dst,'dev':DEV,'metric':42760,'protocol':'static'} for dst in OP['routes']]
            elif args[2:]==['address','show','dev','mgmt']:value=[{'addr_info':[{'local':'192.0.2.2','prefixlen':30}]}]
            elif args[2:5]==['-4','route','get']:
                destination=args[-1];value=[{'dev':'mgmt' if destination=='192.0.2.1' else 'underlay' if destination=='203.0.113.2' else 'different-fib-device'}]
            else:raise AssertionError('unexpected gateway command')
            return types.SimpleNamespace(returncode=0,stdout=json.dumps(value).encode())
        class FakePath:
            def __init__(self,path):self.path=path
            def read_text(self):
                if self.path=='/etc/heliopause-disposable-lab':return json.dumps(MARKER)
                if self.path=='/proc/sys/kernel/random/boot_id':return BOOT
                raise AssertionError('unexpected gateway file')
        output=io.StringIO()
        with patch.dict(sys.modules,{'pathlib':types.SimpleNamespace(Path=FakePath)}),patch.object(subprocess,'run',side_effect=command),patch.object(verifier.time,'time',return_value=201),patch('builtins.open',side_effect=AssertionError('escaped gateway open')),patch.object(os,'open',side_effect=AssertionError('escaped gateway os.open')),contextlib.redirect_stdout(output):
            exec(verifier.gateway_probe_code(MARKER,DEV,OP['routes']),{})
        return json.loads(output.getvalue()),calls
    def test_generated_program_executes_and_collects_real_fib_queries(self):
        gateway,calls=self.collect()
        self.assertEqual(gateway['bootId'],BOOT)
        for route in OP['routes']:self.assertIn(['ip','-j','-4','route','get',route.split('/')[0]],calls)
        checks=verifier.evaluate(gateway,OP,{key:{'success':True} for key in ['forward','reverse','management']})
        self.assertTrue(checks['route']);self.assertFalse(checks['fib'])
        self.assertTrue(checks['handshake']);self.assertTrue(checks['protected'])
    def test_foreign_peer_handshake_does_not_satisfy_approved_peer(self):
        gateway,_=self.collect();gateway['handshakes']='foreign-peer\t200'
        checks=verifier.evaluate(gateway,OP,{key:{'success':True} for key in ['forward','reverse','management']})
        self.assertFalse(checks['handshake'])


if __name__=='__main__':unittest.main()
