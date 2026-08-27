# packaging/systemd

두 유닛과 그 환경파일 예시. **실증되지 않은 지시자는 여기에 없다** — 아래 "실측으로 정해진 것"이 각 항목의 근거다.

| 파일 | 대상 |
|------|------|
| `heliopause-agent.service` | 정책을 적용하는 호스트 전부 (python3, root + `CAP_NET_ADMIN`) |
| `heliopause-agent-applier.conf` | 지정된 Cilium 적용자 한 대만 쓰는 kubeconfig 가시성 drop-in |
| `heliopause-enroll.service` · `.timer` | 호스트가 로컬 키로 CSR을 만들고 승인된 인증서를 회수 |
| `heliopause-agent.path` | 회수된 `agent.pem` 이 나타나는 순간 에이전트를 켠다 — 등록으로 부팅하는 호스트용 |
| `heliopause-relay.service` | 각 VPC의 gw (node 22+, `DynamicUser`, 무권한) |
| `heliopause-revocation-writer.service` · `.socket` | relay가 직접 수정할 수 없는 단조 폐기목록 writer |
| `heliopause-revocations.conf` | 잠긴 writer 계정과 relay socket 제출 보조그룹 (`sysusers.d`) |
| `agent.env.example` · `relay.env.example` | `/etc/heliopause/`에 놓을 환경파일 |

## 0. 인증서 — 먼저

**외부 PKI가 필요하지 않다.** heliopause가 자체 발급한다.

```bash
node bin/heliopause-pki.ts site ./pki policy/dev.ts
```

사이트 모듈에서 호스트 목록을 읽으므로 **발행자가 렌더하는 대상과 인증서를 받는 대상이 같은 출처**다. 한쪽에만 있는 호스트는 하트비트를 못 하고, 하트비트를 못 하는 호스트는 다음 세대를 영원히 못 받는다.

```
pki/ca.pem                  → 모든 호스트의 /etc/heliopause/pki/ca.pem
pki/agent-<host>.pem|.key   → 그 호스트의 agent.pem | agent.key
pki/relay-<gw>.pem|.key     → gw의 relay.pem | relay.key
```

**파일명에 `relay-`·`agent-` 접두가 붙는 이유**: gw는 중계자와 자기 에이전트를 함께 돌리므로 **CN이 같은 인증서 두 장**이 필요하다. CN으로만 이름을 지으면 두 번째 발급이 첫 번째를 조용히 덮고, 남는 것은 SAN 없는 `clientAuth` — 즉 **모든 에이전트가 거부하는 중계자 인증서**다(부록 A V29 ①).

키는 전부 `0600 root:root`. 중계자 키는 유닛이 `LoadCredential`로 읽으므로 `DynamicUser`가 직접 읽을 필요가 없다.

함대 상태를 읽을 오퍼레이터 인증서는 **별도 역할**로 발급한다.

```bash
node bin/heliopause-pki.ts issue ./pki ops-alice --role=operator
# 그 CN을 중계자의 HELIOPAUSE_OPERATOR_CNS에 추가한다
node bin/heliopause-status.ts https://10.17.0.1:8443 --pki=./pki
```

**에이전트 인증서로는 `/status`를 읽을 수 없다**(403). 에이전트는 자기 룰셋을 받고 자기 상태를 보고하지만, 함대 전체 뷰는 모든 호스트의 신원·세대·드리프트 여부를 담는다 — 한 대를 장악한 쪽에게는 다음 표적 목록이자 "지금 보호되지 않는 호스트" 목록이다. 유효한 인증서를 가진 것만으로는 부족하고, 중계자가 CN을 정확히 일치로 확인한다. 와일드카드나 접두 규칙은 없다.

만료 관리:

```bash
node bin/heliopause-pki.ts status ./pki    # 30일 이내면 exit 1 — cron/CI가 파싱 없이 감지
node bin/heliopause-pki.ts renew  ./pki    # 같은 CA로 재발급 (앵커 불변, 호스트별 교체 가능)
```

리프 수명이 90일인 것은 의도다 — **한 번도 안 일어난 만료는 검증된 적 없는 만료다.**

## 설치

에이전트 — 정책을 받는 모든 호스트:

```bash
install -d -m 755 /opt/heliopause/agent
install -m 644 agent/heliopause-pull.py /opt/heliopause/agent/
install -d -m 700 /etc/heliopause/pki
install -m 640 packaging/systemd/agent.env.example /etc/heliopause/agent.env   # 편집할 것
install -m 644 packaging/systemd/heliopause-agent.service /etc/systemd/system/
restorecon -R /opt/heliopause /etc/heliopause      # SELinux Enforcing 환경
systemctl daemon-reload && systemctl enable --now heliopause-agent
```

공용 유닛은 `/etc/rancher/k3s/k3s.yaml`, `/etc/kubernetes/admin.conf`, 전용 kubeconfig까지 모두
`InaccessiblePaths`로 가린 **비적용자 프로필**이다. Cilium 적용자 한 대에서만 다음을 추가한다.

```bash
install -d -m 700 /etc/systemd/system/heliopause-agent.service.d
install -m 644 packaging/systemd/heliopause-agent-applier.conf \
  /etc/systemd/system/heliopause-agent.service.d/applier.conf
install -m 600 ./heliopause-agent.kubeconfig /etc/heliopause/kubeconfig
systemctl daemon-reload && systemctl restart heliopause-agent
```

`packaging/kubernetes/heliopause-agent-rbac.yaml`은 ServiceAccount와 아직 아무 namespace에도
결속되지 않은 최소권한 역할을 만든다. `heliopause-agent-rolebinding.example.yaml`을
`HELIOPAUSE_K8S_NAMESPACES`의 각 namespace마다 복사·수정해 RoleBinding으로 결속한다.
**ClusterRoleBinding은 만들지 않는다.** 권한은 CiliumNetworkPolicy의 get/create/update/delete와
selector 집행 확인에 필요한 Pod get/list뿐이다. 전용 kubeconfig는 이 ServiceAccount만 사용하고
`0600`으로 설치한다. 에이전트는 kubeconfig 미설정, 일반 k3s/Kubernetes admin 경로, 느슨한 파일 모드,
빈 namespace allowlist를 모두 첫 `kubectl` 전에 거부한다.

이 역할에는 `kube-system` ConfigMap/Pod 조회나 `pods/exec`가 없다. 따라서 Cilium의 서비스 맵
관측(`ciliumExposure`)도 기본 비활성이다. 그 관측은 CNP 적용·selector 집행 gate에 필요하지 않고,
Cilium Pod 안에서 명령을 실행할 권한은 CNP CRUD보다 훨씬 크다. 별도 보안 검토로 해당 권한을
명시적으로 부여한 배포만 `HELIOPAUSE_CILIUM_EXPOSURE=1`을 설정한다.

새 호스트는 개인키를 중앙으로 복사하는 대신 등록 타이머를 먼저 실행할 수 있다. 일회성
`stnode_…` 토큰을 `/var/lib/heliopause-agent/enroll-token`에 `0600 root:root`로 놓고, `agent.env`의
enrollment 항목을 채운다. 스크립트는 P-256 키와 CSR을 한 번만 만들며 승인 대기 중에는 같은
요청 ID만 조회한다.

토큰 자리가 `/etc/heliopause/` 가 **아닌** 이유: 등록 유닛은 `ProtectSystem=strict` 라 `ReadWritePaths`
(`/etc/heliopause/pki` · `/var/lib/heliopause-agent`) 밖은 root 에게도 읽기 전용이다. 2026-08-27 까지
여기에는 `/etc/heliopause/enroll-token` 이 적혀 있었고, 그러면 설치 뒤 스크립트의 토큰 삭제가 `EROFS`
로 실패한다 — 비치명이라 등록은 끝나지만 토큰이 TTL 까지 남고 `ConditionPathExists` 가 계속 참이라
타이머가 5분마다 no-op 을 반복한다. stardust 가 첫 호스트를 만들기 전에 유닛 파일에서 읽어 냈다(교환
102 §4). `/etc/heliopause` 를 통째로 여는 대신 파일을 이미 쓰기 가능한 디렉터리로 옮겼다 — 그쪽이
`agent.env` 까지 쓰기 가능해지는 것을 짚었고 맞다.

**토큰 발급에 외부 시스템은 필요 없다.** 매니저에 `HELIOPAUSE_ENROLLMENT_STORE` 를 걸면 등록
저장소가 곧 발급처다 — Dispatcher·데이터베이스·IdP 중 무엇도 전제하지 않는다. 예전 판에는
"Dispatcher가 발급한" 이라고 적혀 있었고 그것은 지금 틀린 문장이다.

```bash
node bin/heliopause-enrollment.ts init ./enrollment.json          # 배포당 딱 한 번
node bin/heliopause-enrollment.ts token-create ./enrollment.json host-01.example --actor=ops-alice
```

`init` 은 기존 파일을 덮어쓰지 않고, 매니저와 모든 쓰기 명령은 없거나 깨진 저장소를 거부한다 —
지워진 폐기 원장을 무해한 첫 기동으로 넘겨짚지 않는다. 인증서 폐기가 한 번이라도 들어간 뒤에는
`init` 을 다시 돌리지 말고 백업에서 복원할 것.

```bash
install -m 644 agent/heliopause-enroll.py /opt/heliopause/agent/
install -m 644 packaging/systemd/heliopause-enroll.{service,timer} /etc/systemd/system/
install -m 644 packaging/systemd/heliopause-agent.path /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now heliopause-enroll.timer
systemctl enable --now heliopause-agent.path        # `heliopause-agent` 자체는 enable 하지 않는다
```

등록으로 부팅하는 호스트에서는 위의 `systemctl enable --now heliopause-agent` 를 **하지 않는다.**
인증서가 오기 전의 에이전트는 `ssl_context()` 에서 죽고, 유닛이 `Restart=always` ·
`StartLimitIntervalSec=0` 이라 서명이 올 때까지 5초마다 다시 죽는다 — 해는 없지만 저널이 「깨진
에이전트」로 읽힌다. `heliopause-agent.path` 가 대신 `/etc/heliopause/pki/agent.pem` 을 지켜보다
켠다. `heliopause-enroll.py` 는 `ca.pem` 을 먼저, `agent.pem` 을 마지막에 각각 원자 rename 으로
쓰므로 그 파일이 보이는 순간 번들 전체가 있다. 재부팅 뒤에도 같은 경로로 뜬다 — 파일이 이미
있으면 path 유닛이 부팅 즉시 서비스를 당긴다.

`HELIOPAUSE_ENROLL_URL` 은 **매니저의 등록 이름**이다(이 배포에서는 `node-enroll.tinyuniver.se`).
Dispatcher 나 다른 수집 이름이 아니다 — 그 이름으로 보내면 엉뚱한 서버가 401 을 주고, 타이머는
5분마다 영원히 재시도하며, 콘솔에는 아무것도 뜨지 않는다. 「승인 대기인가 보다」로 읽히는
무증상 오배송이다.

CSR은 매니저 콘솔의 **등록**(`/app/enrollment`, 상태별로 `pending`·`conflict`·`rejected`·
`signed`) 화면에서 DER SHA-256 지문을 **별도 채널로** 대조해 승인하고, 오프라인 서명기로 발급한
인증서를 업로드한다. 콘솔 없이 같은 일을 하는 CLI 는 아래와 같다.

```bash
node bin/heliopause-enrollment.ts csr-list https://manager.example:8444 --pki=./pki
node bin/heliopause-pki.ts sign-csr ./offline-ca ./host.csr ./host.pem \
  --name=host-01.example --expect-sha256=<위에서 대조한 지문>
node bin/heliopause-enrollment.ts cert-upload https://manager.example:8444 REQUEST_ID \
  --cert=./host.pem --ca-name=site --pki=./pki
```

`--expect-sha256` 은 선택이 아니다 — 지문 없이 서명하면 대조 단계가 통째로 사라진다.

설치 완료 뒤에는 상태 파일을 `completed`로 기록하여 타이머가 등록 엔드포인트를 다시 호출하지
않는다. 스크립트가 소모된 토큰 파일을 스스로 지우고(`ConditionPathExists` 로 타이머 발화가
no-op 이 된다 — 실패가 아니라 종착 상태다), `heliopause-agent.path` 가 에이전트를 켠다. 사람이
할 일은 남지 않는다. 예전 판의 「그 뒤 토큰 파일을 제거하고 agent 를 시작한다」는 두 동작 다
이제 자동이다.

중계자 — gw만:

```bash
install -d -m 755 /opt/heliopause
cp -r src bin /opt/heliopause/
install -m 640 packaging/systemd/relay.env.example /etc/heliopause/relay.env   # 편집할 것
install -m 644 packaging/systemd/heliopause-relay.service /etc/systemd/system/
install -m 644 packaging/systemd/heliopause-revocation-writer.{service,socket} /etc/systemd/system/
install -m 644 packaging/systemd/heliopause-revocations.conf /etc/sysusers.d/
systemd-sysusers /etc/sysusers.d/heliopause-revocations.conf
chmod 600 /etc/heliopause/pki/relay.key       # LoadCredential이 의미를 갖는 전제
restorecon -R /opt/heliopause /etc/heliopause
systemctl daemon-reload
# 잠긴 전용 writer 계정의 StateDirectory에서 빈 폐기 목록을 딱 한 번만 만든다. 이후 이
# 파일이 사라지면 writer와 relay는 재생성하지 않고 기동/업데이트를 거부한다.
systemd-run --wait --collect --unit=heliopause-revocations-init \
  --property=User=heliopause-revocation-writer \
  --property=Group=heliopause-revocation-writer \
  --property=StateDirectory=heliopause-revocations \
  --property=StateDirectoryMode=0755 \
  /usr/bin/node /opt/heliopause/bin/heliopause-revocations.ts \
  init /var/lib/heliopause-revocations/revocations.json
systemctl enable --now heliopause-revocation-writer.socket
systemctl enable --now heliopause-relay
```

디렉터리는 유닛의 `StateDirectory`가 만든다. **세 역할이 서로 다른 디렉터리를 쓴다:**

| 경로 | 소유 | 용도 |
|------|------|------|
| `/var/lib/heliopause-agent/` | 에이전트 (`0700`) | 롤백 약속 · 적용 상태 |
| `/var/lib/heliopause/` | 중계자 (`DynamicUser`의 private `StateDirectory`, `0700`) | `artifacts/`; 중계자만 읽고 쓴다 |
| `/var/lib/heliopause-revocations/` | 잠긴 writer 계정 (`0755`; snapshot `0644`) | 중계자는 읽기만, writer만 원자 교체 |

**중계자의 산출물 디렉터리는 2026-08-03 부터 쓰기 가능하다.** 그전에는 `ReadOnlyPaths` 였고, 산출물이 ssh 로 도착하던 동안에는 그것이 맞았다. `POST /publish` 가 생기면서 두 층이 막았다 — `EROFS`(systemd 하드닝), 그것을 풀자 `EACCES`(유닉스 소유권). 중계자는 `DynamicUser` 라 UID 가 transient 이므로 **`chown` 이 아니라 `StateDirectory`** 로 고쳤다. chown 은 systemd 가 UID 를 재배정하는 날 조용히 깨진다. 이제 manager는 mTLS `POST /publish`만 사용하고, relay 프로세스가 자기 private 디렉터리에 기록한다. `0700` 부모 때문에 SSH로 직접 산출물을 복사하는 레거시 경로는 root(또는 그와 동등한 권한)만 가능하며 정상 발행 경로가 아니다.

`StateDirectory` 를 쓰면 relay 실데이터가 `/var/lib/private/heliopause` 로 가고 `/var/lib/heliopause` 는 systemd 가 유지하는 심볼릭 링크가 된다. 부모는 `StateDirectoryMode=0700`이고 매 기동 시 그 유닛의 transient UID에 귀속된다. `HELIOPAUSE_ARTIFACT_DIR`은 `/var/lib/heliopause/artifacts`를 가리킨다.

폐기목록은 의도적으로 다른 StateDirectory다. writer를 relay와 다른 **고정·로그인 불가 계정**으로 두는 이유는 `DynamicUser` StateDirectory가 root-only `/var/lib/private` 아래로 이동해 다른 DynamicUser인 relay가 `0644` 파일조차 순회할 수 없기 때문이다. writer 계정은 `/var/lib/heliopause-revocations`의 `0755` 부모와 `0644` snapshot을 소유한다. relay는 파일을 읽을 수 있지만 부모 write 권한이 없고, `ReadOnlyPaths`가 두 번째 장벽이라 atomic rename·unlink·truncate를 할 수 없다. 파일 bind mount는 writer의 atomic rename 뒤 relay가 이전 inode를 계속 보므로 사용하지 않는다. relay가 가진 정적 `heliopause-revocations` 보조그룹은 `0660` Unix socket 연결에만 쓰이며 snapshot 파일 소유권은 주지 않는다. writer는 strict schema, 본문/row 상한과 기존 row 단조성을 다시 검사한다. 따라서 손상된 relay가 빈 snapshot이나 기존 row rewrite를 요청해도 파일은 바뀌지 않는다. 계정과 그룹을 만들기 전에 unit을 시작하면 안전하게 실패하므로 위 `systemd-sysusers` 순서를 생략하면 안 된다.

**같은 디렉터리를 쓰면 안 된다.** 에이전트의 `StateDirectoryMode=0700`이 공유 부모에 걸리면 `DynamicUser`인 중계자가 `artifacts/`에 진입할 수 없다. gw는 둘을 함께 돌리는 유일한 호스트라 여기서만 나타나고, 순서가 고약하다 — 중계자를 먼저 올려 정상 동작한 뒤 **에이전트 시작이 중계자를 소급해서 깨뜨린다.** 원인은 바뀐 유닛이 아니라 다른 유닛의 저널에 있다.

## 실측으로 정해진 것

2026-07-31, gw-01.dev (Rocky 10 · systemd 257 · nftables 1.1.5 · SELinux **Enforcing**)에서 확인. 검증 후 호스트는 원상복구했다.

### `StartLimitIntervalSec`가 `[Service]`에 있으면 조용히 버려진다

`systemd-analyze verify`가 **rc=0으로 통과하면서** 경고 한 줄만 남기고 무시한다. 확인 방법은 파싱 결과를 직접 읽는 것뿐이다:

```
systemctl show -p StartLimitIntervalUSec heliopause-agent   # → 0 이어야 한다
```

이 설정이 하는 일이 "다섯 번 죽으면 `failed`로 고정되는 것을 막는" 것이라, 무시되면 **정확히 막으려던 상태로 돌아간다.** `[Unit]`에 있어야 한다.

### 에이전트 샌드박스에서 nft와 `nft monitor` 모두 동작한다

`nft` 테이블 생성·체인·룰·덤프·삭제를 전 지시자 적용 상태로 통과시켰고, `nft monitor`가 변경을 스트리밍하는 것도 확인했다 — H28이 파싱하는 `# new generation N by process <pid>` 줄까지 포함해서. 실효 권한은 `cap_net_admin` 단독(`CapEff: 0000000000001000`).

`ProtectKernelModules`는 **일부러 빼뒀다.** 모듈 자동 로드를 막으면 정상 세대가 아티팩트만 봐서는 알 수 없는 이유로 적용 실패한다.

### `DynamicUser` + `LoadCredential`은 실제로 키를 가린다

`0600 root:root` 키에 대해 런타임 UID(64952)가 **직접 읽기 실패**했고, 중계자는 `%d` 사본으로 mTLS 핸드셰이크를 완료했다. 신원 결속도 유닛 아래에서 동작한다:

```
CN=k3s-01.dev 인증서로 host="gw-01.dev" 주장 → 403
```

`%d`는 유닛 지시자에서만 치환된다. 세 PKI 경로를 `relay.env`에 두면 문자 그대로 전달되어 열 수 없는 경로를 넘기게 된다.

### `MemoryDenyWriteExecute`는 중계자에 걸 수 없다

V8이 JIT다. 에이전트(python)에는 걸려 있다.

## `nohup` 실증이 놓친 것

V20 실호스트 실증은 `nohup`으로 띄웠고, 그래서 **아무것도 프로세스를 재시작하지 않았다.** `Restart=always`가 붙는 순간 다음 경로가 열린다:

1. 이전 상태·절대 기한을 `prepared`로 fsync → 타이머 무장 → 관리 경로를 끊는 룰셋 적용
2. 타이머가 발화하기 전에 프로세스 사망 (948MB 호스트의 OOM, 배포 중 재시작)
3. systemd가 새 프로세스를 띄운다. **타이머와 백업은 메모리에 있었다.** 둘 다 없다
4. 경로가 끊겼으므로 하트비트는 전부 실패하고, 실패를 알아차릴 코드에는 도달하지 않는다

호스트는 `pending`을 디스크에 든 채 **영구히 잠긴다** — 이 설계가 막으려는 바로 그 결과다.

그래서 되돌릴 대상과 **절대 시각**을 커널을 건드리기 **전에** 디스크에 적는다. 이 단계는
`prepared`라서 하트비트로 확인될 수 없다. 적용과 로컬 read-back을 마친 뒤에만 `pending`으로
fsync한다. `prepared` 상태에서 재시작하면 side effect 유무가 불명확하므로 첫 하트비트 전에
identity-bound restore를 즉시 실행한다. 남은 시간이 아니라 절대 시각인 이유는, 크래시 루프가
매 기동마다 기한을 미루면 잠긴 상태가 무한히 연장되기 때문이다. 상태 파일은 고유 임시 파일을
fsync하고 atomic rename한 뒤 부모 디렉터리도 fsync한다. `agent/test_validate.py`의
`TestRestartWhilePending`이 이 interleaving들을 고정한다:

| 확인 | 결과 |
|------|------|
| 기한 경과 후 기동 | 즉시 롤백, 잠금 룰 제거 |
| 기한 이전 기동 | 남은 시간(13s)만큼 재무장, 조기 발화 없음 |
| 재무장 후 실제 경로 절단 | 하트비트 실패 → 타이머 발화 → 테이블 제거 |
| 백업 기록 없는 `pending` | 우리 테이블만 삭제 (heliopause 이전 상태 = 도달 가능) |
| `confirmed` 상태 기동 | 커널 무접촉 — 에이전트 업그레이드가 방화벽을 흔들지 않는다 |
| 남의 테이블 | `netavark` · `firewalld` 전 구간 무변경 |
