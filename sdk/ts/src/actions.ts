import { MULTISIG_TAG, decodeAddress, encodeAddress } from "./bech32.js";
import { Writer, asBuffer, fromHex, toHex } from "./bincode.js";

/** These indices are ActionPayload's positional bincode discriminants. Never derive them. */
export const ACTION_VARIANT = {
  transfer: 0, joinValidator: 1, leaveValidator: 2, stake: 3, unstake: 4, registerBlsKey: 6,
  authorizeOperator: 8, revokeOperator: 9, grantAttestation: 10, revokeAttestation: 11,
  registerAsset: 12, issueAsset: 13, transferAsset: 14, freezeAsset: 18, unfreezeAsset: 19,
  burnAsset: 21, setHolderFrozen: 22, lockHolderAmount: 23, unlockHolderAmount: 24,
  issuerForcedTransfer: 25, recoverHolder: 26, issueAssetTo: 27,
  setAssetLimits: 31,
} as const;
const CLASS = { other: 0, real_estate: 1, equity: 2, bond: 3, stablecoin: 4, commodity: 5 } as const;
const TOPIC = { kyc: 0, aml: 1, accredited: 2, jurisdiction: 3 } as const;
export type AssetClass = keyof typeof CLASS;
export type ClaimTopic = keyof typeof TOPIC;
export type AssetMetadata = { asset_class: AssetClass; decimals: number; required_claims: ClaimTopic[]; allowed_jurisdictions: string[] | null; max_supply: string | bigint | null; metadata_uri: string | null; symbol: string; name: string };
export const ACTION_FEE = 1_000_000n;

export function encodeTransfer(to: string, amount: bigint): Uint8Array { return new Writer().varint(ACTION_VARIANT.transfer).string(to).varint(amount).bytes(); }
export function encodeJoinValidator(validator: string, stake: bigint, blsPubkey: Uint8Array, blsPop: Uint8Array): Uint8Array { return new Writer().varint(ACTION_VARIANT.joinValidator).string(validator).varint(stake).vec(Array.from(blsPubkey), (w, b) => w.u8(b)).vec(Array.from(blsPop), (w, b) => w.u8(b)).bytes(); }
export function encodeLeaveValidator(validator: string): Uint8Array { return new Writer().varint(ACTION_VARIANT.leaveValidator).string(validator).bytes(); }
export function encodeStake(validator: string, amount: bigint): Uint8Array { return new Writer().varint(ACTION_VARIANT.stake).string(validator).varint(amount).bytes(); }
export function encodeUnstake(validator: string, amount: bigint): Uint8Array { return new Writer().varint(ACTION_VARIANT.unstake).string(validator).varint(amount).bytes(); }
export function encodeRegisterBlsKey(validator: string, pubkey: Uint8Array, pop: Uint8Array): Uint8Array { return new Writer().varint(ACTION_VARIANT.registerBlsKey).string(validator).vec(Array.from(pubkey), (w, b) => w.u8(b)).vec(Array.from(pop), (w, b) => w.u8(b)).bytes(); }
export function encodeAuthorizeOperator(operator: string): Uint8Array { return new Writer().varint(ACTION_VARIANT.authorizeOperator).string(operator).bytes(); }
export function encodeRevokeOperator(): Uint8Array { return new Writer().varint(ACTION_VARIANT.revokeOperator).bytes(); }
export function encodeGrantAttestation(subject: string, hash: string, topics: ClaimTopic[], jurisdiction: string | null): Uint8Array { return new Writer().varint(ACTION_VARIANT.grantAttestation).string(subject).string(hash).vec(topics, (w, topic) => w.varint(TOPIC[topic])).option(jurisdiction, (w, value) => w.string(value)).bytes(); }
export function encodeRevokeAttestation(subject: string): Uint8Array { return new Writer().varint(ACTION_VARIANT.revokeAttestation).string(subject).bytes(); }
export function encodeRegisterAsset(assetId: string, complianceRequired: boolean, metadata: AssetMetadata): Uint8Array { return new Writer().varint(ACTION_VARIANT.registerAsset).string(assetId).bool(complianceRequired).varint(CLASS[metadata.asset_class]).u8(metadata.decimals).vec(metadata.required_claims, (w, topic) => w.varint(TOPIC[topic])).option(metadata.allowed_jurisdictions, (w, codes) => w.vec(codes, (ww, code) => ww.string(code))).option(metadata.max_supply, (w, cap) => w.varint(BigInt(cap))).option(metadata.metadata_uri, (w, uri) => w.string(uri)).string(metadata.symbol).string(metadata.name).bytes(); }
export function encodeIssueAsset(asset: string, amount: bigint): Uint8Array { return new Writer().varint(ACTION_VARIANT.issueAsset).string(asset).varint(amount).bytes(); }
export function encodeTransferAsset(asset: string, to: string, amount: bigint): Uint8Array { return new Writer().varint(ACTION_VARIANT.transferAsset).string(asset).string(to).varint(amount).bytes(); }
export function encodeFreezeAsset(asset: string, frozen: boolean, reason: string): Uint8Array { return new Writer().varint(frozen ? ACTION_VARIANT.freezeAsset : ACTION_VARIANT.unfreezeAsset).string(asset).string(reason).bytes(); }
export function encodeBurnAsset(asset: string, amount: bigint): Uint8Array { return new Writer().varint(ACTION_VARIANT.burnAsset).string(asset).varint(amount).bytes(); }
export function encodeSetHolderFrozen(asset: string, holder: string, frozen: boolean): Uint8Array { return new Writer().varint(ACTION_VARIANT.setHolderFrozen).string(asset).string(holder).bool(frozen).bytes(); }
export function encodeLockHolderAmount(asset: string, holder: string, amount: bigint, lock: boolean): Uint8Array { return new Writer().varint(lock ? ACTION_VARIANT.lockHolderAmount : ACTION_VARIANT.unlockHolderAmount).string(asset).string(holder).varint(amount).bytes(); }
export function encodeIssuerForcedTransfer(asset: string, from: string, to: string, amount: bigint, reason: string): Uint8Array { return new Writer().varint(ACTION_VARIANT.issuerForcedTransfer).string(asset).string(from).string(to).varint(amount).string(reason).bytes(); }
export function encodeRecoverHolder(asset: string, lost: string, replacement: string): Uint8Array { return new Writer().varint(ACTION_VARIANT.recoverHolder).string(asset).string(lost).string(replacement).bytes(); }
export function encodeIssueAssetTo(asset: string, to: string, amount: bigint): Uint8Array { return new Writer().varint(ACTION_VARIANT.issueAssetTo).string(asset).string(to).varint(amount).bytes(); }
/** Sets issuer-controlled investor, concentration, and attestation-age limits. `null` clears each limit. */
export function encodeSetAssetLimits(asset: string, maxHolders: number | null, maxBalancePerHolder: bigint | null = null, maxAttestationAge: bigint | null = null): Uint8Array { return new Writer().varint(ACTION_VARIANT.setAssetLimits).string(asset).option(maxHolders, (w, value) => w.varint(value)).option(maxBalancePerHolder, (w, value) => w.varint(value)).option(maxAttestationAge, (w, value) => w.varint(value)).bytes(); }
export function signingBytes(sender: string, nonce: number | bigint, payload: Uint8Array): Uint8Array { return new Writer().string(sender).varint(nonce).raw(payload).bytes(); }
export async function signAction(privateKey: CryptoKey, sender: string, nonce: number, payload: Uint8Array): Promise<string> { return toHex(new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, asBuffer(signingBytes(sender, nonce, payload))))); }
export type SignedAction = { sender: string; nonce: number; signature: string; payload: number[] };
export function submitBody(sender: string, nonce: number, signature: string, payload: Uint8Array): SignedAction { return { sender, nonce, signature, payload: Array.from(payload) }; }

/** M-of-N sender, mirrors `xc_primitives::multisig_address`. Every member signs with plain `signAction(key, multisigAddress, nonce, payload)`; `multisigSignature` combines exactly `threshold` of them into the action's `signature` field. */
export const MAX_MULTISIG_MEMBERS = 16;
const compareBytes = (a: Uint8Array, b: Uint8Array): number => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };
function multisigPolicy(threshold: number, members: Uint8Array[]): Uint8Array[] { const sorted = [...members].sort(compareBytes); if (!sorted.length || sorted.length > MAX_MULTISIG_MEMBERS) throw new Error("member count must be 1..=16"); if (!Number.isInteger(threshold) || threshold < 1 || threshold > sorted.length) throw new Error("threshold must be 1..=members"); if (sorted.some((m, i) => m.length !== 32 || (i > 0 && compareBytes(sorted[i - 1], m) >= 0))) throw new Error("members must be unique 32-byte keys"); return sorted; }
async function policyHash(threshold: number, sorted: Uint8Array[]): Promise<Uint8Array> { const domain = new TextEncoder().encode("arxium-multisig-v1"), input = new Uint8Array(domain.length + 2 + 32 * sorted.length); input.set(domain); input.set([threshold, sorted.length], domain.length); sorted.forEach((m, i) => input.set(m, domain.length + 2 + 32 * i)); return new Uint8Array(await crypto.subtle.digest("SHA-256", input)); }
export async function multisigAddress(threshold: number, members: Uint8Array[]): Promise<string> { const hash = await policyHash(threshold, multisigPolicy(threshold, members)); return encodeAddress(Uint8Array.from([MULTISIG_TAG, ...hash])); }
/** `signatures`: [member public key, that member's hex signature]. */
export function multisigSignature(threshold: number, members: Uint8Array[], signatures: [Uint8Array, string][]): string { const sorted = multisigPolicy(threshold, members); const indexed = signatures.map(([key, sig]) => { const index = sorted.findIndex((m) => compareBytes(m, key) === 0); if (index < 0) throw new Error("signer is not a member"); return [index, fromHex(sig)] as const; }).sort((a, b) => a[0] - b[0]); const out = new Writer().raw(Uint8Array.from([threshold, sorted.length])); sorted.forEach((m) => out.raw(m)); indexed.forEach(([index, sig]) => out.raw(Uint8Array.from([index])).raw(sig)); return toHex(out.bytes()); }
/** Same checks as `Action::verify_signature` for a multisig sender. */
export async function verifyMultisig(sender: string, signature: string, message: Uint8Array): Promise<boolean> { const sent = decodeAddress(sender), witness = fromHex(signature), [threshold, n] = witness; if (sent.length !== 33 || witness.length !== 2 + 32 * n + 65 * threshold) return false; const members = Array.from({ length: n }, (_, i) => witness.slice(2 + 32 * i, 34 + 32 * i)); const hash = await policyHash(threshold, multisigPolicy(threshold, members)); if (compareBytes(hash, sent.slice(1)) !== 0) return false; let last = -1; for (let at = 2 + 32 * n; at < witness.length; at += 65) { const index = witness[at]; if (index >= n || index <= last) return false; last = index; const key = await crypto.subtle.importKey("raw", asBuffer(members[index]), "Ed25519", false, ["verify"]); if (!await crypto.subtle.verify("Ed25519", key, asBuffer(witness.slice(at + 1, at + 65)), asBuffer(message))) return false; } return true; }
