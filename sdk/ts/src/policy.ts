import { Reader, Writer, asBuffer, fromHex, toHex } from "./bincode.js";
import { multisigAddress, multisigSignature, signAction, verifyMultisig } from "./actions.js";

export const ACCOUNT_POLICY_ACTION = 42;
export const POLICY_VARIANT = { setAccountPolicy: 0, rotateAccountMembers: 1, addSessionKey: 2, revokeSessionKey: 3, startAccountRecovery: 4, cancelAccountRecovery: 5, executeAccountRecovery: 6 } as const;
export type ThresholdPolicy = { threshold: number; members: string[] };
export type SpendAsset = "native" | { asset: string };
export type SpendingLimit = { asset: SpendAsset; periodBlocks: string; amount: string };
export type SessionKey = { publicKey: string; expiresAt: string; asset: SpendAsset; allowance: string; recipients: string[] };
export type AccountPolicy = { owners: ThresholdPolicy; limits: SpendingLimit[]; recipients: string[] | null; sessions: SessionKey[]; recovery: { guardians: ThresholdPolicy; delayBlocks: string } | null };
export type PolicyMode = "owner" | "session" | "guardian";
const MODE = { owner: 0, session: 1, guardian: 2 } as const;

function key(hex: string): Uint8Array { const bytes = fromHex(hex); if (bytes.length !== 32) throw new Error("public key must be 32 bytes"); return bytes; }
function bounded(value: string, bits: number): bigint { const n = BigInt(value); if (n < 0n || n >= 1n << BigInt(bits)) throw new Error(`value outside u${bits}`); return n; }
function threshold(w: Writer, p: ThresholdPolicy): void {
  if (!Number.isInteger(p.threshold) || p.threshold < 1 || p.threshold > p.members.length || p.members.length > 16 || p.members.some((m, i) => i > 0 && p.members[i - 1] >= m)) throw new Error("threshold policy must have 1..16 sorted unique members");
  w.u8(p.threshold).vec(p.members, (ww, m) => ww.raw(key(m)));
}
function asset(w: Writer, a: SpendAsset): void { if (a === "native") w.varint(0); else w.varint(1).string(a.asset); }
function recipients(w: Writer, list: string[]): void { if (list.length > 64 || list.some((a, i) => i > 0 && list[i - 1] >= a)) throw new Error("recipients must be bounded, unique and sorted"); w.vec(list, (ww, a) => ww.string(a)); }
function session(w: Writer, s: SessionKey): void { w.raw(key(s.publicKey)).varint(bounded(s.expiresAt, 64)); asset(w, s.asset); w.varint(bounded(s.allowance, 128)); recipients(w, s.recipients); }
function policy(w: Writer, p: AccountPolicy): void {
  threshold(w, p.owners);
  if (p.limits.length > 16 || p.sessions.length > 16) throw new Error("policy exceeds bounded menu");
  if (p.sessions.length && !p.limits.some(l => l.asset === "native")) throw new Error("session keys require a native fee budget");
  w.vec(p.limits, (ww, l) => { asset(ww, l.asset); if (BigInt(l.periodBlocks) === 0n) throw new Error("period must be positive"); ww.varint(bounded(l.periodBlocks, 64)).varint(bounded(l.amount, 128)); });
  w.option(p.recipients, recipients).vec(p.sessions, session).option(p.recovery, (ww, r) => { threshold(ww, r.guardians); if (BigInt(r.delayBlocks) === 0n) throw new Error("recovery delay must be positive"); ww.varint(bounded(r.delayBlocks, 64)); });
}
export function encodeAccountPolicy(name: keyof typeof POLICY_VARIANT, input: Record<string, any>): Uint8Array {
  const w = new Writer().varint(ACCOUNT_POLICY_ACTION).varint(POLICY_VARIANT[name]);
  switch (name) {
    case "setAccountPolicy": policy(w, input.policy); break;
    case "rotateAccountMembers": case "startAccountRecovery": threshold(w, input.owners); break;
    case "addSessionKey": session(w, input.session); break;
    case "revokeSessionKey": w.raw(key(input.publicKey)); break;
    case "cancelAccountRecovery": case "executeAccountRecovery": break;
  }
  return w.bytes();
}
function readKey(r: Reader): string { return toHex(Uint8Array.from({ length: 32 }, () => r.u8())); }
function readThreshold(r: Reader): ThresholdPolicy { return { threshold: r.u8(), members: r.vec(readKey) }; }
function readAsset(r: Reader): SpendAsset { const tag = r.varint(); if (tag === 0n) return "native"; if (tag === 1n) return { asset: r.string() }; throw new Error("unknown spend asset"); }
function readSession(r: Reader): SessionKey { return { publicKey: readKey(r), expiresAt: r.varint().toString(), asset: readAsset(r), allowance: r.varint().toString(), recipients: r.vec(rr => rr.string()) }; }
export function readAccountPolicy(r: Reader): { name: keyof typeof POLICY_VARIANT; input: Record<string, any> } {
  const variant = Number(r.varint()), name = Object.keys(POLICY_VARIANT).find(n => POLICY_VARIANT[n as keyof typeof POLICY_VARIANT] === variant) as keyof typeof POLICY_VARIANT | undefined;
  if (!name) throw new Error("unknown account policy action");
  let input: Record<string, any>;
  switch (name) {
    case "setAccountPolicy": input = { policy: { owners: readThreshold(r), limits: r.vec(rr => ({ asset: readAsset(rr), periodBlocks: rr.varint().toString(), amount: rr.varint().toString() })), recipients: r.option(rr => rr.vec(v => v.string())), sessions: r.vec(readSession), recovery: r.option(rr => ({ guardians: readThreshold(rr), delayBlocks: rr.varint().toString() })) } }; break;
    case "rotateAccountMembers": case "startAccountRecovery": input = { owners: readThreshold(r) }; break;
    case "addSessionKey": input = { session: readSession(r) }; break;
    case "revokeSessionKey": input = { publicKey: readKey(r) }; break;
    default: input = {};
  }
  return { name, input };
}
/** Sign the stable account's envelope, not the signer's personal address. */
export async function signPolicyMember(privateKey: CryptoKey, sender: string, nonce: number, payload: Uint8Array): Promise<string> { return signAction(privateKey, sender, nonce, payload); }
export function assemblePolicySignature(mode: Exclude<PolicyMode, "session">, policy: ThresholdPolicy, signatures: [string, string][]): string {
  if (signatures.length !== policy.threshold || new Set(signatures.map(([m]) => m)).size !== signatures.length || signatures.some(([, s]) => fromHex(s).length !== 64)) throw new Error("need exactly threshold distinct member signatures");
  return `a7${MODE[mode].toString(16).padStart(2, "0")}${multisigSignature(policy.threshold, policy.members.map(key), signatures.map(([m, s]) => [key(m), s]))}`;
}
export function assembleSessionSignature(publicKey: string, signature: string): string { if (fromHex(signature).length !== 64) throw new Error("signature must be 64 bytes"); return `a701${toHex(key(publicKey))}${signature}`; }
/** Cryptographic verification only; use proven policy at the action's pre-state.
 * The runtime also checks capability scope, expiry, nonce and spend counters. */
export async function verifyPolicySignature(policy: AccountPolicy, signature: string, message: Uint8Array): Promise<PolicyMode | null> {
  try {
    const bytes = fromHex(signature); if (bytes[0] !== 0xa7) return null;
    if (bytes[1] === 1) {
      if (bytes.length !== 98) return null;
      const pk = bytes.slice(2, 34); if (!policy.sessions.some(s => s.publicKey === toHex(pk))) return null;
      const cryptoKey = await crypto.subtle.importKey("raw", asBuffer(pk), "Ed25519", false, ["verify"]);
      return await crypto.subtle.verify("Ed25519", cryptoKey, asBuffer(bytes.slice(34)), asBuffer(message)) ? "session" : null;
    }
    const p = bytes[1] === 0 ? policy.owners : bytes[1] === 2 ? policy.recovery?.guardians : null;
    if (!p) return null;
    return await verifyMultisig(await multisigAddress(p.threshold, p.members.map(key)), toHex(bytes.slice(2)), message) ? (bytes[1] === 0 ? "owner" : "guardian") : null;
  } catch { return null; }
}
