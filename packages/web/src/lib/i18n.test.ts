import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { actionWord, certaintyWord, contradictionKind, crumbLabel, denyModeWord, directionWord, endpointKind, hostStateWord, LANGS, layerWord, MESSAGES, originWord, pickLang, protoWord, t, type MessageKey, whereWord } from "./i18n.ts";

describe("the catalogue", () => {
  it("does not declare a key twice", () => {
    const src = readFileSync(new URL("./i18n.ts", import.meta.url), "utf8");
    const keys = [...src.matchAll(/^\s+"([^"]+)": \{/gm)].map((m) => m[1]);
    const counts = new Map<string, number>();
    for (const key of keys) counts.set(key, (counts.get(key) ?? 0) + 1);
    const dups = [...counts].filter(([, n]) => n > 1).map(([k]) => k);
    assert.deepEqual(dups, [], `declared twice: ${dups.join(", ")}`);
  });

  it("keeps the fleet stale chip a word, not the policy banner", () => {
    assert.equal(t("en", "m.stale"), "stale");
    assert.equal(t("ko", "m.stale"), "낡음");
    assert.match(t("en", "m.policyStale", { rendered: "aaa", repo: "bbb" }), /aaa/);
  });

  it("keeps the fleet lede a claim, in both languages", () => {
    assert.match(t("en", "m.fleetLede"), /missing answer is not an empty fleet/);
    assert.match(t("ko", "m.fleetLede"), /빈 함대가 아니다/);
  });

  it("does not drop the negation from the address-space heading", () => {
    assert.match(t("en", "s.addressSpace.heading"), /not an inventory/);
    assert.match(t("ko", "s.addressSpace.heading"), /인벤토리가 아니다/);
  });

  it("says what lookup cannot see", () => {
    assert.match(t("en", "m.lookupCaveat"), /NetworkPolicy/);
    assert.match(t("ko", "m.lookupCaveat"), /NetworkPolicy/);
  });

  it("does not leave the named English leftovers in Korean", () => {
    assert.equal(t("ko", "m.fresh").includes("fresh"), false);
    assert.match(t("ko", "m.fresh"), /렌더된 커밋이 저장소의 최신/);
    assert.equal(t("ko", "m.diffUnavailable").includes("unavailable"), false);
    const range = t("ko", "m.diffRange", { base: "aaa", head: "bbb", n: 1 });
    assert.equal(/\bbase\b/i.test(range), false);
    assert.equal(/\bhead\b/i.test(range), false);
    assert.match(range, /aaa/);
    assert.match(range, /bbb/);
    const published = t("ko", "m.publishNote", { generation: "g1", target: "dev", serving: "g2" });
    assert.equal(published.includes("serving"), false);
    assert.match(published, /g2/);
    assert.equal(t("ko", "m.pipeConflictNote").includes("conflict"), false);
    assert.match(t("ko", "m.pipeConflictNote"), /승인도 거절도/);
    assert.equal(t("ko", "m.policyRows").includes("catch-all"), false);
    assert.match(t("ko", "m.policyRows"), /제외/);
    assert.equal(t("ko", "m.findingPlacement").includes("placement"), false);
    assert.match(t("ko", "m.findingPlacement"), /미판정/);
    assert.equal(t("ko", "m.emptyEnroll").includes("/enrollment"), false);
    const unapproved = t("ko", "m.unapproved", { n: 2, names: "dev-1" });
    assert.equal(unapproved.includes("unapproved"), false);
    assert.match(unapproved, /외부 레지스트리/);
    const readAt = t("en", "m.readAt", { at: "12:00" });
    assert.match(readAt, /12:00/);
    assert.equal(readAt.startsWith("readAt"), false);
  });

  it("has Korean for every English string", () => {
    const missing = Object.entries(MESSAGES)
      .filter(([, v]) => !(v as { ko?: string }).ko)
      .map(([k]) => k);
    assert.deepEqual(missing, [], `no Korean for: ${missing.join(", ")}`);
  });

  it("uses the same placeholders in both languages", () => {
    const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const [key, v] of Object.entries(MESSAGES)) {
      const entry = v as { en: string; ko?: string };
      if (!entry.ko) continue;
      assert.deepEqual(holes(entry.ko), holes(entry.en), `${key} placeholders differ`);
    }
  });

  it("has no empty string on either side", () => {
    for (const [key, v] of Object.entries(MESSAGES)) {
      const entry = v as { en: string; ko?: string };
      assert.ok(entry.en.trim(), `${key} has an empty en`);
      if (entry.ko !== undefined) assert.ok(entry.ko.trim(), `${key} has an empty ko`);
    }
  });
});

describe("t", () => {
  it("returns the language asked for", () => {
    assert.equal(t("en", "nav.fleet"), "fleet");
    assert.equal(t("ko", "nav.fleet"), "함대");
  });

  it("substitutes placeholders", () => {
    assert.equal(t("en", "m.intrusion", { n: 2 }), "intrusion 2");
    assert.equal(t("ko", "m.intrusion", { n: 2 }), "개입 2");
  });

  it("leaves an unknown placeholder visible rather than blanking it", () => {
    assert.match(t("en", "rule.saved", { commit: "a" }), /\{branch\}/);
  });
});

describe("pickLang", () => {
  it("prefers an explicit choice", () => {
    assert.equal(pickLang({ override: "ko", acceptLanguage: "en-US" }), "ko");
    assert.equal(pickLang({ override: "en", acceptLanguage: "ko-KR" }), "en");
  });

  it("ignores an override it does not have", () => {
    assert.equal(pickLang({ override: "fr", acceptLanguage: "ko" }), "ko");
  });

  it("matches the primary subtag", () => {
    assert.equal(pickLang({ acceptLanguage: "ko-KR,ko;q=0.9,en;q=0.8" }), "ko");
    assert.equal(pickLang({ acceptLanguage: "en-GB,en;q=0.9" }), "en");
  });

  it("defaults to English", () => {
    assert.equal(pickLang({}), "en");
    assert.equal(pickLang({ acceptLanguage: "fr,de" }), "en");
  });
});

describe("actionWord", () => {
  it("names allow and deny in the language asked for, and leaves an unknown verb", () => {
    assert.equal(actionWord("ko", "allow"), "허용");
    assert.equal(actionWord("ko", "deny"), "거부");
    assert.equal(actionWord("en", "deny"), "deny");
    assert.equal(actionWord("ko", "log"), "log");
  });
});

describe("layerWord", () => {
  it("names host and workload in the language asked for", () => {
    assert.equal(layerWord("ko", "host"), "호스트");
    assert.equal(layerWord("ko", "workload"), "워크로드");
    assert.equal(layerWord("en", "host"), "host");
    assert.equal(layerWord("ko", "hook"), "hook");
  });
});

describe("whereWord", () => {
  it("names src, dst and ports in the language asked for", () => {
    assert.equal(whereWord("ko", "src"), "출발지");
    assert.equal(whereWord("ko", "dst"), "목적지");
    assert.equal(whereWord("ko", "ports"), "포트");
    assert.equal(whereWord("en", "src"), "source");
    assert.equal(whereWord("ko", "notes"), "notes");
  });
});

describe("originWord", () => {
  it("names kernel origin, not the verdict sentence", () => {
    assert.equal(originWord("ko", "automatic"), "자동");
    assert.equal(originWord("en", "automatic"), "automatic");
    assert.notEqual(originWord("en", "automatic"), t("en", "v.automatic"));
    assert.equal(originWord("ko", "static"), "정적");
    assert.equal(originWord("ko", "unstated"), "미기재");
  });
});

describe("directionWord", () => {
  it("names ingress and egress in the language asked for", () => {
    assert.equal(directionWord("ko", "ingress"), "인바운드");
    assert.equal(directionWord("ko", "egress"), "아웃바운드");
    assert.equal(directionWord("en", "egress"), "egress");
  });
});

describe("denyModeWord", () => {
  it("names drop and reject in the language asked for", () => {
    assert.equal(denyModeWord("ko", "drop"), "드롭");
    assert.equal(denyModeWord("ko", "reject"), "거절");
    assert.equal(denyModeWord("en", "drop"), "drop");
  });
});

describe("hostStateWord", () => {
  it("names the closed host states and leaves an unknown one", () => {
    assert.equal(hostStateWord("ko", "rolled-back"), "되돌아감");
    assert.equal(hostStateWord("en", "rolled-back"), "rolled-back");
    assert.equal(hostStateWord("ko", "pending"), "대기");
    assert.equal(hostStateWord("ko", "none"), "없음");
    assert.equal(hostStateWord("ko", "applying"), "applying");
  });
});

describe("contradictionKind", () => {
  it("names the closed kinds and leaves an unknown slug", () => {
    assert.equal(contradictionKind("en", "artifact-hash-wrong"), "artifact-hash-wrong");
    assert.equal(contradictionKind("ko", "artifact-hash-wrong"), "아티팩트 해시가 틀림");
    assert.equal(contradictionKind("ko", "unknown-generation"), "알 수 없는 세대");
    assert.equal(contradictionKind("ko", "new-kind"), "new-kind");
  });
});

describe("certaintyWord", () => {
  it("names certain and unexplained in the language asked for", () => {
    assert.equal(certaintyWord("ko", "certain"), "확실");
    assert.equal(certaintyWord("ko", "unexplained"), "설명 안 됨");
    assert.equal(certaintyWord("en", "certain"), "certain");
    assert.equal(certaintyWord("ko", "maybe"), "maybe");
  });
});

describe("protoWord", () => {
  it("names the closed protos and leaves an unknown slug", () => {
    assert.equal(protoWord("en", "tcp"), "tcp");
    assert.equal(protoWord("en", "udp"), "udp");
    assert.equal(protoWord("en", "icmp"), "icmp");
    assert.equal(protoWord("en", "any"), "any");
    assert.equal(protoWord("ko", "tcp"), "TCP");
    assert.equal(protoWord("ko", "udp"), "UDP");
    assert.equal(protoWord("ko", "icmp"), "ICMP");
    assert.equal(protoWord("ko", "any"), "임의");
    assert.notEqual(protoWord("ko", "any"), t("ko", "v.any"));
    assert.equal(protoWord("ko", "sctp"), "sctp");
  });
});

describe("endpointKind", () => {
  it("names the closed kinds and leaves an unknown slug", () => {
    assert.equal(endpointKind("en", "host"), "host");
    assert.equal(endpointKind("en", "host-group"), "host-group");
    assert.equal(endpointKind("en", "k8s-namespace"), "k8s-namespace");
    assert.equal(endpointKind("ko", "host"), "호스트");
    assert.equal(endpointKind("ko", "host-group"), "호스트 그룹");
    assert.equal(endpointKind("ko", "cidr"), "대역");
    assert.equal(endpointKind("ko", "object"), "객체");
    assert.equal(endpointKind("ko", "internet"), "인터넷");
    assert.equal(endpointKind("ko", "any"), "모두");
    assert.equal(endpointKind("ko", "k8s-namespace"), "네임스페이스");
    assert.equal(endpointKind("ko", "k8s-label"), "레이블");
    assert.notEqual(endpointKind("ko", "any"), protoWord("ko", "any"));
    assert.equal(endpointKind("ko", "fqdn"), "fqdn");
  });
});

describe("crumbLabel", () => {
  it("translates a screen name and a policy section the same way the bar draws them", () => {
    assert.equal(crumbLabel("en", "policy"), "policy");
    assert.equal(crumbLabel("ko", "policy"), "정책");
    assert.equal(crumbLabel("en", "files"), "files");
    assert.equal(crumbLabel("ko", "files"), "파일");
    assert.equal(crumbLabel("en", "address-space"), "address space");
    assert.equal(crumbLabel("ko", "unknown"), "unknown");
  });
});

describe("the language list", () => {
  it("is exactly the two that are supported", () => {
    assert.deepEqual([...LANGS], ["en", "ko"]);
    const k: MessageKey = "s.zones";
    assert.ok(t("ko", k).length > 0);
  });
});
