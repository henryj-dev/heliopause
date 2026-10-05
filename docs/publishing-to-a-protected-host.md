# 보호 호스트가 있는 사이트를 발행하기 — prod · util, 그리고 az01

`protectedHosts` 를 선언한 사이트는 **명시적 opt-in 없이 발행되지 않는다.** 이 문서는 그때 치는
명령과, 그 게이트가 **무엇을 막고 무엇을 안 막는지** 적는다.

적는 이유는 하나다 — **그 게이트가 한동안 없었고, 없는 동안 적힌 문서도 없었다.** 선언은
`prod.ts`·`util.ts` 에 「적용에 `allowProtected` 가 필요하다」고 몇 달째 있었는데 집행하는 코드가
없었고(2026-10-05 실측), 그 사실도 이 저장소 어디에도 없었다. 집행이 돌아온 지금(`#101`) 절차가
적힌 자리가 필요하다.

## 어느 사이트가 해당하나

| 사이트 | 보호 호스트 | 그 사이트에서 차지하는 비중 |
|---|---|---|
| `prod-icn-vtr` | `^gw-01\.` | **유일 호스트.** 모든 발행에 플래그가 필요하다 |
| `util-icn-vtr` | `^gw-01\.` | **유일 호스트.** 같다 |
| `dev-icn-vtr` | `^gw-01\.` | 6대 중 하나. **그 호스트를 포함하는 발행에만** |
| `az01-icn-own` | `^gw-01\.` | 3대 중 하나(Pi). 같다 |

🔴 **prod·util 은 「보호 호스트를 건드릴 때만」이 아니라 항상이다.** 그 사이트의 유일 호스트가
보호 호스트이므로, 플래그 없는 발행은 `nothing to publish — no hosts given` 이 아니라 **그 호스트를
이유로 거부**된다.

## CLI — `--allow-protected`

```bash
cd ~/github/mack-erel/heliopause/policy && git pull --ff-only   # 심링크 실체를 먼저 최신화
cd ~/github/henryj-dev/heliopause                                # 도구가 사는 곳

node bin/heliopause-publish.ts policy/prod.ts prod-icn-vtr \
  --propose=https://10.17.0.10:30444 --pki=pki --operator=ops-henry-review \
  --allow-protected
```

플래그가 없으면 이렇게 거부된다:

```
gw-01.prod-icn-vtr is a protected host — pass allowProtected to include it.
Protected hosts are the ones whose failure takes out more than themselves.
  Re-run with --allow-protected if that is what you mean.
```

⚠️ **오타는 플래그 없음과 같지 않다.** 이 CLI 는 플래그 이름을 검증하지 않으므로 `--allow-protexted`
같은 것은 조용히 무시될 수 있었다. 근사형(`--allow-prot…`)은 **exit 2 로 거부**하고 철자를 알려
준다 — 「답했다고 생각한 거부」를 보는 일을 막기 위한 것이다.

## 승인 — `--show` 를 먼저

```bash
# 🔴 승인 전에. 이것 없이 승인하는 것은 해시 비교이고 규칙에 대한 검사가 아니다
node bin/heliopause-approve.ts <manager> <plan-sha256> --show \
  --pki=pki --operator=ops-henry-review

# 승인은 다른 운영자여야 한다
node bin/heliopause-approve.ts <manager> <plan-sha256> --approve \
  --pki=pki --operator=ops-henry
```

`--show` 에 이 줄이 있어야 한다:

```
protected  🔴 this plan reaches a protected host and the proposer opted in (--allow-protected). …
```

**없으면 그 플랜은 opt-in 을 담고 있지 않다.** 그 문장은 호스트 행보다 **위에** 인쇄된다 — 아래에
있으면 결정이 끝난 뒤에 읽히기 때문이다.

### 운영자 둘은 서로 달라야 한다

제안 `ops-henry-review` · 승인 `ops-henry`. ⚠️ **`ops-ci` 는 매니저에 등록돼 있지 않다.** 그리고
**자기 승인은 CLI 로 불가능하다** — 인증서에 역할 주장이 없어서이고, 브라우저 경로에 OTP 가 있다.

## 콘솔

콘솔도 거부한다. 보호 호스트가 걸리면 `POST /api/policy/plan` 이 **409 + `needsAllowProtected`** 로
답하고, 화면이 그 문장과 함께 확인을 받아 `allowProtected: true` 로 **다시 보낸다.**

400 이 아니라 409 인 이유: 요청은 정상이고 정책도 렌더됐다. **빠진 것은 결정**이다.

미리 체크박스를 두지 않은 이유: 어느 호스트가 보호 대상인지 **렌더 전에는 알 수 없어** 매번 묻게
되고, **매번 뜨는 확인은 읽지 않고 누르는 확인**이다.

### 🔴 콘솔은 매니저 이미지가 새 판으로 배포된 뒤부터 거부한다

게이트는 세 자리에 있고 그중 **둘이 매니저 안**이다:

| 자리 | 어디서 도나 | 언제부터 |
|---|---|---|
| 발행 CLI | 이 저장소의 코드를 직접 | **지금부터** |
| 콘솔 제안 | 매니저 | **그 이미지가 배포된 뒤** |
| 정책 워커 | 매니저 | 같음 |

**그 사이에 콘솔로 prod·util 을 발행하면 확인 없이 지나간다.** 배포 전에는 CLI 를 쓰거나, 콘솔을
쓰더라도 `--show` 로 그 `protected` 줄을 직접 확인할 것.

## 자동 정책 워커는 opt-in 할 수 없다

워커는 **보호 호스트를 제외하고** 제안하며 그 사실을 로그에 남긴다. 플래그를 스스로 켤 수 있으면
opt-in 이 아니라 **단계가 하나 더 있는 기본값**이기 때문이다.

⚠️ prod·util 처럼 보호 호스트가 **유일 호스트**인 사이트에서는 그 필터가 목록을 비우고
`planPublish` 가 `nothing to publish — no hosts given` 으로 거부한다. **즉 그 두 사이트는 워커가
자동으로 제안하지 않는다** — 사람이 위 CLI 나 콘솔로 해야 한다.

## 🔴 이 게이트가 묻지 않는 것

플래그는 **「이 세대가 게이트웨이에 닿는다는 것을 사람이 말했는가」**만 묻는다. **그 규칙이 맞는지는
묻지 않는다.** 실제로 게이트웨이를 지키는 것은 셋이다:

1. **발행 전 렌더 확인** — `--propose` 없이 돌려 그 호스트의 룰셋을 눈으로 본다.
2. **2인 승인 + OTP.**
3. **`gateway` 단계를 마지막에 두기** — `ROLLOUT_ORDER` 가 `canary → general → gateway` 다.

플래그는 **네 번째가 아니라 2번을 또렷하게 만드는 장치**다: opt-in 이 플랜 해시에 들어가므로
플래그 없는 플랜에 준 승인을 플래그 있는 플랜에 **재사용할 수 없고**, `--show` 가 승인자에게 그
사실을 문장으로 인쇄한다.

### 그리고 권한 검사가 아니다

매니저는 **정책을 갖지 않는다** — 그러니 제출된 번들에서 `protectedHosts` 를 평가할 수 없고,
opt-in 을 주장하는 번들은 **그 말을 믿는다.** 막는 것은 코드가 아니라 **두 번째 운영자**다.
이것을 「서버가 검증한다」로 읽으면 안 된다.

## 왜 게이트가 한동안 없었나

집행 지점은 **push 전송의 적용 클라이언트**(`src/agent.ts`)에 있었다:

```ts
if (isProtectedHost(cfg, host) && !opts.allowProtected) {
  return { ok: false, host, steps,
    error: `${host} is a protected host — pass allowProtected to apply to it` };
}
```

그 파일이 `12d39c3`(2026-08-15 감사 대응, 서명 아티팩트로 옮긴 커밋)에서 **삭제됐다.** pull 에서는
에이전트가 스스로 아티팩트를 당기므로 그런 호출자가 없어졌고, 검사는 **살 곳이 없어 멈췄다.**
누가 잊은 것이 아니라 전송이 바뀐 결과다. `#101` 이 되살린 것이 그것이다.

⚠️ 그 사이에 **`6cf0140`(iperf)이 prod·util 에 플래그 없이 발행됐다.** 선언은 게이트가 있다고
적고 있었고 발행한 사람은 그것을 읽었다. 그것이 이 문서가 존재하는 이유다 — **선언이 있는 것과
집행되는 것은 다르고, 그 차이는 문서가 아니라 코드에만 적혀 있었다.**
