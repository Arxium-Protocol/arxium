const U8_MAX = 250n;
const U16_MAX = 0xffffn;
const U32_MAX = 0xffff_ffffn;
const U64_MAX = 0xffff_ffff_ffff_ffffn;
const U128_MAX = (1n << 128n) - 1n;

/** Canonical bincode 2.x `config::standard()` writer for Arxium action payloads. */
export class Writer {
  private chunks: number[] = [];
  bytes(): Uint8Array { return Uint8Array.from(this.chunks); }
  raw(bytes: Uint8Array | number[]): this { for (const byte of bytes) this.chunks.push(byte); return this; } // not push(...bytes): spreading overflows the call stack past ~100k bytes
  u8(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 255) throw new RangeError(`u8 out of range: ${value}`);
    this.chunks.push(value); return this;
  }
  bool(value: boolean): this { return this.u8(value ? 1 : 0); }
  varint(value: bigint | number): this {
    const v = BigInt(value);
    if (v < 0n || v > U128_MAX) throw new RangeError(`varint out of range: ${v}`);
    if (v <= U8_MAX) return this.u8(Number(v));
    if (v <= U16_MAX) return this.u8(0xfb).le(v, 2);
    if (v <= U32_MAX) return this.u8(0xfc).le(v, 4);
    if (v <= U64_MAX) return this.u8(0xfd).le(v, 8);
    return this.u8(0xfe).le(v, 16);
  }
  private le(value: bigint, width: number): this { for (let i = 0; i < width; i++) { this.chunks.push(Number(value >> BigInt(i * 8) & 0xffn)); } return this; }
  string(value: string): this { const bytes = new TextEncoder().encode(value); return this.varint(bytes.length).raw(bytes); }
  option<T>(value: T | null | undefined, write: (writer: Writer, value: T) => void): this { if (value == null) return this.u8(0); this.u8(1); write(this, value); return this; }
  vec<T>(values: readonly T[], write: (writer: Writer, value: T) => void): this { this.varint(values.length); for (const value of values) write(this, value); return this; }
}
/** A fresh ArrayBuffer holding exactly `bytes`. Not `bytes.slice().buffer`: Node's Buffer.slice() is a view, so `.buffer` would be the whole shared pool. */
export const asBuffer = (bytes: Uint8Array): ArrayBuffer => new Uint8Array(bytes).buffer;
export function toHex(bytes: Uint8Array): string { return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""); }
export function fromHex(hex: string): Uint8Array { if (hex.length % 2 || !/^[0-9a-f]*$/i.test(hex)) throw new Error("invalid hex"); return Uint8Array.from(hex.match(/../g)?.map((byte) => Number.parseInt(byte, 16)) ?? []); }
/** Reads what `Writer` writes. Pair every decode with a re-encode check (see `decodePayload`) rather than trusting it to reject non-canonical input. */
export class Reader {
  private at = 0;
  constructor(private readonly data: Uint8Array) {}
  u8(): number { if (this.at >= this.data.length) throw new RangeError("unexpected end of payload"); return this.data[this.at++]; }
  bool(): boolean { const value = this.u8(); if (value > 1) throw new RangeError(`invalid bool: ${value}`); return value === 1; }
  varint(): bigint {
    const tag = this.u8();
    if (tag <= 250) return BigInt(tag);
    const width = ({ 0xfb: 2, 0xfc: 4, 0xfd: 8, 0xfe: 16 } as Record<number, number>)[tag];
    if (!width) throw new RangeError(`invalid varint tag: ${tag}`);
    let value = 0n;
    for (let i = 0; i < width; i++) value |= BigInt(this.u8()) << BigInt(i * 8);
    return value;
  }
  length(): number { const len = this.varint(); if (len > BigInt(this.data.length - this.at)) throw new RangeError("length past end of payload"); return Number(len); }
  string(): string { const len = this.length(), text = new TextDecoder("utf-8", { fatal: true }).decode(this.data.subarray(this.at, this.at + len)); this.at += len; return text; }
  option<T>(read: (reader: Reader) => T): T | null { return this.bool() ? read(this) : null; }
  vec<T>(read: (reader: Reader) => T): T[] { return Array.from({ length: this.length() }, () => read(this)); }
  done(): void { if (this.at !== this.data.length) throw new RangeError("trailing bytes after payload"); }
}
