import { signAction, signingBytes, submitBody, verifyMultisig, type SignedAction } from "./actions.js";
import { decodeAddress, isMultisigAddress } from "./bech32.js";
import { asBuffer, fromHex } from "./bincode.js";
import { verifyPolicySignature, type AccountPolicy } from "./policy.js";

export type RpcOptions = { rpc: string; token?: string; fetch?: typeof globalThis.fetch };
export type ActionStatus = { status: "pending" } | { status: "confirmed"; height: number; block_hash: string; sender: string; nonce: number } | { status: "dropped"; reason: string } | { status: "unknown" };
export type SendActionOptions = { privateKey: CryptoKey; sender: string; payload: Uint8Array; pollIntervalMs?: number; timeoutMs?: number; finalized?: boolean };
export class RpcError extends Error { constructor(readonly status: number, message: string) { super(message); } }

export class ArxiumRpc {
  readonly rpc: string;
  private readonly token?: string;
  private readonly requestFetch: typeof globalThis.fetch;
  constructor(options: RpcOptions) { this.rpc = options.rpc.replace(/\/+$/, ""); this.token = options.token; this.requestFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init)); } // browsers and Workers throw "Illegal invocation" if fetch is called with `this` = ArxiumRpc
  private async request<T>(path: string, init?: RequestInit): Promise<T> { const response = await this.requestFetch(`${this.rpc}${path}`, { ...init, headers: { ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}), ...init?.headers } }); const text = await response.text(); if (!response.ok) throw new RpcError(response.status, text || `${response.status} ${response.statusText}`); return text ? JSON.parse(text) as T : undefined as T; }
  private genesis?: Promise<Uint8Array>;
  /** This chain's genesis hash, fetched once per client; every signature binds it. */
  genesisHash(): Promise<Uint8Array> { return this.genesis ??= this.request<{ genesis_hash: string }>("/genesis-hash").then((r) => fromHex(r.genesis_hash.replace(/^0x/, "")), (e) => { this.genesis = undefined; throw e; }); }
  status<T = Record<string, unknown>>(): Promise<T> { return this.request("/status"); }
  account<T = Record<string, unknown>>(address: string): Promise<T> { return this.request(`/accounts/${encodeURIComponent(address)}`); }
  stake<T = Record<string, unknown>>(address: string): Promise<T> { return this.request(`/accounts/${encodeURIComponent(address)}/stake`); }
  stakes<T = Record<string, unknown>[]>(address: string): Promise<T> { return this.request(`/accounts/${encodeURIComponent(address)}/stakes`); }
  blsKey<T = Record<string, unknown>>(address: string): Promise<T> { return this.request(`/accounts/${encodeURIComponent(address)}/bls-key`); }
  submit(action: SignedAction): Promise<unknown> { return this.request("/actions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(action) }); }
  async action(signature: string): Promise<ActionStatus> { try { return await this.request<ActionStatus>(`/actions/${encodeURIComponent(signature)}`); } catch (error) { if (error instanceof RpcError && error.status === 404) return { status: "unknown" }; throw error; } }
  blocks<T = unknown>(from: number, to: number): Promise<T> { return this.request(`/blocks?from=${from}&to=${to}`); }
  block<T = unknown>(height: number): Promise<T> { return this.request(`/blocks/${height}`); }
  blockByHash<T = unknown>(hash: string): Promise<T> { return this.request(`/blocks/by-hash/${encodeURIComponent(hash)}`); }
  validators<T = unknown>(): Promise<T> { return this.request("/validators"); }
  finality<T = unknown>(): Promise<T> { return this.request("/finality"); }
  search<T = unknown>(query: string): Promise<T> { return this.request(`/search?q=${encodeURIComponent(query)}`); }
  minStake<T = unknown>(): Promise<T> { return this.request("/min-stake"); }
  actionFee<T = unknown>(): Promise<T> { return this.request("/action-fee"); }
  async sendAction(options: SendActionOptions): Promise<{ action: SignedAction; status: ActionStatus }> { const account = await this.account<{ nonce: number }>(options.sender).catch((error) => { if (error instanceof RpcError && error.status === 404) return { nonce: 0 }; throw error; }); const signature = await signAction(options.privateKey, await this.genesisHash(), options.sender, account.nonce, options.payload); const action = submitBody(options.sender, account.nonce, signature, options.payload); await this.submit(action); const deadline = Date.now() + (options.timeoutMs ?? 120_000); while (Date.now() < deadline) { const status = await this.action(signature); if (status.status === "dropped") throw new Error(`action dropped: ${status.reason}`); if (status.status === "confirmed") { if (!options.finalized) return { action, status }; const block = await this.block<{ finalized?: boolean }>(status.height); if (block.finalized) return { action, status }; } await new Promise((resolve) => setTimeout(resolve, options.pollIntervalMs ?? 1_000)); } throw new Error("timed out waiting for action"); }
}
/** Stateful witnesses require the policy at the action's pre-state, not today's
 * policy. This checks cryptography; circuit execution proves limits and scope. */
export async function verifySignedAction(action: SignedAction, genesis: Uint8Array, preStatePolicy?: AccountPolicy): Promise<boolean> { try {
  const message = signingBytes(genesis, action.sender, action.nonce, Uint8Array.from(action.payload));
  if (action.signature.length > 128 && /^a7(00|01|02)/.test(action.signature)) return !!preStatePolicy && await verifyPolicySignature(preStatePolicy, action.signature, message) !== null;
  if (isMultisigAddress(action.sender)) return await verifyMultisig(action.sender, action.signature, message);
  const key = await crypto.subtle.importKey("raw", asBuffer(decodeAddress(action.sender)), "Ed25519", false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, asBuffer(fromHex(action.signature)), asBuffer(message));
} catch { return false; } }
