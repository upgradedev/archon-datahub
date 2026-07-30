// Runtime deny harness for the CI-generated public judge pack.
//
// This preload runs before tsx and the evidence code. It blocks the Node network
// transports and child-process escape hatches that could otherwise turn a deterministic
// fixture projection into an undeclared live call. The generator and verifier both
// require the marker below when they run in GitHub Actions.

import childProcess from "node:child_process";
import dgram from "node:dgram";
import dns from "node:dns";
import dnsPromises from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";

const marker = Symbol.for("archon.judge-evidence.network-deny/v1");

if (globalThis[marker] !== true) {
  const denied = () => {
    throw new Error(
      "External network and child-process access are denied while producing judge evidence."
    );
  };

  for (const [target, names] of [
    [http, ["get", "request"]],
    [https, ["get", "request"]],
    [net, ["connect", "createConnection"]],
    [tls, ["connect"]],
    [dgram, ["createSocket"]],
    [
      dns,
      [
        "lookup",
        "lookupService",
        "resolve",
        "resolve4",
        "resolve6",
        "resolveAny",
        "resolveCaa",
        "resolveCname",
        "resolveMx",
        "resolveNaptr",
        "resolveNs",
        "resolvePtr",
        "resolveSoa",
        "resolveSrv",
        "resolveTxt",
        "reverse",
      ],
    ],
    [
      dnsPromises,
      [
        "lookup",
        "lookupService",
        "resolve",
        "resolve4",
        "resolve6",
        "resolveAny",
        "resolveCaa",
        "resolveCname",
        "resolveMx",
        "resolveNaptr",
        "resolveNs",
        "resolvePtr",
        "resolveSoa",
        "resolveSrv",
        "resolveTxt",
        "reverse",
      ],
    ],
    [
      childProcess,
      [
        "exec",
        "execFile",
        "execFileSync",
        "execSync",
        "fork",
        "spawn",
        "spawnSync",
      ],
    ],
  ]) {
    for (const name of names) {
      if (typeof target[name] === "function") {
        target[name] = denied;
      }
    }
  }

  Object.defineProperty(globalThis, "fetch", {
    configurable: false,
    enumerable: true,
    value: denied,
    writable: false,
  });
  if ("WebSocket" in globalThis) {
    Object.defineProperty(globalThis, "WebSocket", {
      configurable: false,
      enumerable: true,
      value: class DeniedWebSocket {
        constructor() {
          denied();
        }
      },
      writable: false,
    });
  }

  Object.defineProperty(globalThis, marker, {
    configurable: false,
    enumerable: false,
    value: true,
    writable: false,
  });
  syncBuiltinESMExports();
}
