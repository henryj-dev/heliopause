/** Registry-only kernel lock. The helper never reads Registry data or signing keys. */
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, unlinkSync, mkdirSync, openSync, closeSync, fstatSync, constants } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { type StoreFailure } from './json-store.ts';

const holder = `import os,sys,fcntl,stat,select
ready,nonce,parent=sys.argv[1:]
fd=3
s=os.fstat(fd)
if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077:sys.exit(2)
while os.getppid()==int(parent):
 try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
 except BlockingIOError:
  if select.select([sys.stdin],[],[],0.02)[0] and not os.read(sys.stdin.fileno(),1):sys.exit(3)
else:sys.exit(3)
if os.getppid()!=int(parent):sys.exit(3)
out=os.open(ready,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
os.write(out,nonce.encode());os.close(out)
while os.getppid()==int(parent):
 if select.select([sys.stdin],[],[],0.05)[0] and not os.read(sys.stdin.fileno(),1):break
`;
const pause = new Int32Array(new SharedArrayBuffer(4));
export function withNetworkRegistryLock<T>(path: string, fail: StoreFailure, body: () => T): T {
  mkdirSync(dirname(path),{recursive:true,mode:0o700});
  // Old processes used a different lock protocol; never reclaim their pathname automatically.
  if (existsSync(path+'.lock')) throw fail('legacy Registry writer lock requires stopped-writer reconciliation',503);
  const nonce=randomBytes(24).toString('hex'), ready=path+'.ready-'+nonce;
  const fd=openSync(path+'.kernel-lock',constants.O_RDWR|constants.O_CREAT|constants.O_NOFOLLOW|constants.O_NONBLOCK,0o600);
  const info=fstatSync(fd);
  if(!info.isFile()||info.uid!==process.geteuid?.()||(info.mode&0o077)) {closeSync(fd);throw fail('invalid Registry lock inode',503);}
  // Parent and helper share one open-file description: a killed helper cannot release the
  // callback's flock while Node still holds this descriptor.
  const child=spawn('python3',['-c',holder,ready,nonce,String(process.pid)],{stdio:['pipe','ignore','ignore',fd]});
  child.on('error',()=>{});
  try {
    const until=performance.now()+2000;
    while (true) {
      if (existsSync(ready) && readFileSync(ready,'utf8')===nonce) break;
      if (performance.now()>=until) throw fail('Registry kernel lock unavailable or busy',503);
      Atomics.wait(pause,0,0,10);
    }
    return body();
  } finally {
    // OS signal delivery doesn't need the blocked Node event loop to flush child.stdin.end().
    child.kill('SIGTERM');child.stdin!.destroy();closeSync(fd);
    try { unlinkSync(ready); } catch { /* no ready signal was installed */ }
    // The stable kernel-lock inode is deliberately never unlinked.
  }
}
