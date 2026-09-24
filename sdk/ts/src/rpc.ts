import { signAction, signingBytes, submitBody, verifyMultisig, type SignedAction } from "./actions.js";
import { decodeAddress, isMultisigAddress } from "./bech32.js";
import { asBuffer, fromHex } from "./bincode.js";

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
  async sendAction(options: SendActionOptions): Promise<{ action: SignedAction; status: ActionStatus }> { const account = await this.account<{ nonce: number }>(options.sender).catch((error) => { if (error instanceof RpcError && error.status === 404) return { nonce: 0 }; throw error; }); const signature = await signAction(options.privateKey, options.sender, account.nonce, options.payload); const action = submitBody(options.sender, account.nonce, signature, options.payload); await this.submit(action); const deadline = Date.now() + (options.timeoutMs ?? 120_000); while (Date.now() < deadline) { const status = await this.action(signature); if (status.status === "dropped") throw new Error(`action dropped: ${status.reason}`); if (status.status === "confirmed") { if (!options.finalized) return { action, status }; const block = await this.block<{ finalized?: boolean }>(status.height); if (block.finalized) return { action, status }; } await new Promise((resolve) => setTimeout(resolve, options.pollIntervalMs ?? 1_000)); } throw new Error("timed out waiting for action"); }
}
export async function verifySignedAction(action: SignedAction): Promise<boolean> { try { if (isMultisigAddress(action.sender)) return await verifyMultisig(action.sender, action.signature, signingBytes(action.sender, action.nonce, Uint8Array.from(action.payload))); const key = await crypto.subtle.importKey("raw", asBuffer(decodeAddress(action.sender)), "Ed25519", false, ["verify"]); return crypto.subtle.verify("Ed25519", key, asBuffer(fromHex(action.signature)), asBuffer(signingBytes(action.sender, action.nonce, Uint8Array.from(action.payload)))); } catch { return false; } }
