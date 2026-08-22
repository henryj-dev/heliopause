# 아티팩트 서명 키 — 만들기, 배포, 교체

승인된 아티팩트는 매니저의 온라인 Ed25519 키로 서명되고, 에이전트는 자기 방화벽을 건드리기 전에
그 서명을 검증한다. **2인 승인이 "사람이 동의했다" 를 말한다면, 서명은 "호스트에 도착한 바이트가
그 사람이 동의한 그것" 임을 말한다.** 중계자는 서명된 번들을 나를 뿐 만들지 못한다.

이 문서는 키를 만들고 배포하고 교체하는 절차다. 코드는 전부 있으나 키는 사람이 만든다.

## 링이 둘인 이유

| 링 | 키 위치 | 최대 인가 수명 | 쓰는 곳 |
|---|---|---|---|
| `manager` | 매니저 프로세스가 읽는 파일 (온라인) | 7일 | 일상 발행 (`--propose` → 승인 → push) |
| `break-glass` | 매니저 밖 (아래 § 어디에 두는가) | 24시간 | 매니저가 죽었을 때 `--break-glass` 직접 발행 |

두 링을 나누지 않으면 **온라인 키 유출이 곧 장수 비상 인가를 찍어낼 권한**이 된다. 반대로 오프라인
키만 두면 매일의 발행이 오프라인 키를 꺼내게 만들어 그것을 온라인 키로 만든다. 수명 상한이 두 링에
서로 다르게 걸려 있는 것도 같은 이유다.

에이전트는 **집합**을 신뢰한다. 한 링에 키가 여러 개 있어도 되고, 그 사실이 아래 교체 절차를
무중단으로 만든다.

## 만들기

```sh
# 매니저 온라인 키 — 매니저를 돌리는 계정으로, 그 계정만 읽을 수 있게
umask 077
openssl genpkey -algorithm ed25519 -out artifact-signing.key
openssl pkey -in artifact-signing.key -pubout -out artifact-signing.pub

# break-glass 키 — 이 기계가 아닌 곳에서. 개인키는 매니저 호스트에 올라가지 않는다
openssl genpkey -algorithm ed25519 -out break-glass.key
openssl pkey -in break-glass.key -pubout -out break-glass.pub
```

**key id 는 공개키 DER(SubjectPublicKeyInfo)의 SHA-256 이다.** PEM 텍스트의 해시가 아니다 —
같은 키를 다른 줄바꿈으로 저장하면 PEM 해시는 달라지고 DER 해시는 같다.

```sh
openssl pkey -pubin -in artifact-signing.pub -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
# → sha256:<이 값> 을 --key-id 에 쓴다
```

## break-glass 개인키를 어디에 두는가

**한 가지 조건이 절대적이고, 나머지는 저울질이다.** 이 키는 클러스터가 죽었을 때 쓴다 —
그러므로 **꺼내는 데 클러스터가 필요하면 안 된다.** 그래서 SOPS 로 git 에 넣는 선택지는 없다:
복호화 키를 flux 가 클러스터 안에 들고 있으므로, 비상 키가 자기가 복구할 대상에 의존하게 된다.

그 조건을 만족하는 자리는 여럿이고 사는 것이 다르다.

| 자리 | 클러스터 의존 | 워크스테이션 침해 시 | 잃기 쉬움 |
|---|---|---|---|
| 평소 꽂지 않는 물리 매체 | 없음 | **안 털린다** | 분실·부식 |
| 워크스테이션의 암호 관리자 | 없음 | **같이 털린다** (로그인 중이면 잠금 해제 상태) | 낮음 |
| 저장소 디렉터리의 파일 | 없음 | 같이 털린다 | 낮음 |

암호 관리자는 파일보다 낫다 — 쉬는 동안 암호화돼 있고, 실수로 커밋될 자리에 있지 않다.
**그러나 「오프라인」이 아니다.** 노트북이 침해되는 시나리오에서 파일과 같은 값이고, 계정
복구라는 경로가 하나 는다. 그 차이를 알고 고르는 것과 모르고 고르는 것은 다르므로 여기 적는다.

⚠️ **암호 필드에 PEM 을 붙이면 개행이 상할 수 있다.** 꺼냈을 때 파싱되지 않는 키는 필요한
순간에만 그 사실이 드러난다 — 비상 키에서 가장 나쁜 실패다. 넣은 뒤 **반드시 꺼내서** 키 id 가
같은지 확인한다:

```bash
pbpaste > /tmp/k.key && node -e 'const{createPublicKey,createHash}=require("node:crypto");
  const p=createPublicKey(require("node:fs").readFileSync(process.argv[1],"utf8"));
  console.log("sha256:"+createHash("sha256").update(p.export({format:"der",type:"spki"})).digest("hex"))' /tmp/k.key
rm -P /tmp/k.key
```

지우기 전에 확인할 것이 하나 더 있다: **공개 절반이 함대의 신뢰 링에 실제로 들어가 있는가.**
개인키만 옮기고 공개키가 안 깔려 있으면 비상 경로는 이미 없는 것이다.

```bash
ssh <host> 'for f in /etc/heliopause/trust/break-glass/*; do
  openssl pkey -pubin -in "$f" -outform DER | openssl dgst -sha256 -hex; done'
```

## 배포

**매니저** — 개인키 하나만.

```
HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE=/etc/heliopause/artifact-signing.key
```

매니저는 기동 시 이 파일을 읽고, 정규 파일이 아니거나 심볼릭 링크이거나 group/other 에 열려 있거나
소유자가 다르거나 Ed25519 가 아니면 **리스닝 소켓을 열기 전에** 종료한다. 클러스터에서 돌면 이
파일은 Secret 마운트이며 매니페스트는 이 저장소가 아니라 배포 저장소에 있다.

**에이전트** — 공개키만, 링별 디렉터리로.

```
/etc/heliopause/trust/manager/       artifact-signing.pub
/etc/heliopause/trust/break-glass/   break-glass.pub

HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR=/etc/heliopause/trust/manager
HELIOPAUSE_BREAK_GLASS_KEYS_DIR=/etc/heliopause/trust/break-glass
```

디렉터리는 심볼릭 링크가 아니어야 하고 group/other 쓰기가 없어야 하며, 안의 파일도 같다. 에이전트는
**기동 시** 둘 다 읽는다 — 권한이 틀렸거나 Ed25519 가 아닌 파일이 있으면 거기서 종료한다. 세대가
도착할 때가 아니라. 롤아웃 중에 키링이 틀렸다는 것을 알게 되는 것이 이 순서가 막는 일이다.

**두 링 모두 필요하다.** break-glass 를 안 쓸 작정이어도 그렇다. 디렉터리가 없는 것과 링이 빈 것은
검증기에게 같은 것이고, 그러면 설정되지 않은 호스트와 아무것도 신뢰하지 않는 호스트를 구별할 수 없다.

## 교체 — 순서가 전부다

에이전트가 집합을 신뢰하므로 **더하고 → 바꾸고 → 뺀다.**

```
1. 새 공개키를 전 호스트의 manager 링에 추가한다     (이제 두 키를 신뢰)
2. 에이전트를 재시작해 링을 다시 읽게 한다            (기동 시 로드다)
3. 매니저의 HELIOPAUSE_ARTIFACT_SIGNING_KEY_FILE 을 새 개인키로 바꾸고 재시작
4. 한 세대를 발행해 새 키로 서명된 것이 확정되는지 본다
5. 그때서야 옛 공개키를 링에서 뺀다
```

**반대로 하면 창이 생긴다** — 매니저가 새 키로 서명하는데 호스트는 아직 옛 키만 신뢰하는 구간이고,
그 구간에서 발행하면 전 호스트가 아티팩트를 거부한다. 방화벽은 그대로 두고 갱신만 멈추므로 조용하다.

5번을 건너뛰면 유출된 옛 키가 계속 유효하다. 교체는 1~5 를 다 해야 끝난다.

## 침해 시

온라인 키가 샜다고 판단되면:

```
1. 새 매니저 키를 만들고 위 교체를 1~3까지 즉시 진행한다
2. 옛 공개키를 전 호스트 링에서 뺀다 (5번을 앞당긴다)
3. 매니저가 못 뜨면 break-glass 로 직접 발행해 링에서 옛 키를 뺀 세대를 밀어넣는다
```

인가에는 만료가 있으므로(`HELIOPAUSE_ARTIFACT_AUTHORIZATION_TTL_SEC`, 기본 24시간) 이미 서명된
번들의 재생 창은 그 값으로 닫힌다. 그것을 짧게 잡을수록 이 대응에 쓸 수 있는 시간이 는다.

## break-glass 발행

```sh
node bin/heliopause-publish.ts policy/dev.ts /var/lib/heliopause/artifacts \
  --break-glass --target=dev \
  --signing-key=/media/offline/break-glass.key \
  --key-id=sha256:… \
  --authorization-ttl-sec=900
```

`--break-glass` 없이 직접 발행은 거부된다. 일상 변경은 `--propose` 를 지나 두 사람을 거친다 —
직접 발행은 그 통제를 우회하는 경로이므로 명시적으로 그렇게 적어야 한다.
