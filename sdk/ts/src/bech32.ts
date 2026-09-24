const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
export const HRP = "arx";
export const ASSET_HRP = "arxasset";
function polymod(values: number[]): number { let chk = 1; for (const value of values) { const top = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ value; for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GENERATORS[i]; } return chk >>> 0; }
function expand(hrp: string): number[] { return [...hrp].map((char) => char.charCodeAt(0) >>> 5).concat(0, [...hrp].map((char) => char.charCodeAt(0) & 31)); }
function convertBits(data: ArrayLike<number>, from: number, to: number, pad: boolean): number[] { let acc = 0, bits = 0; const out: number[] = [], max = (1 << to) - 1; for (const byte of Array.from(data)) { acc = (acc << from) | byte; bits += from; while (bits >= to) { bits -= to; out.push((acc >>> bits) & max); } } if (pad && bits) out.push((acc << (to - bits)) & max); else if (!pad && (bits >= from || ((acc << (to - bits)) & max))) throw new Error("invalid padding"); return out; }
function encode32(hrp: string, bytes: Uint8Array): string { const data = convertBits(bytes, 8, 5, true); const checksumValue = polymod([...expand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1; const checksum = Array.from({ length: 6 }, (_, i) => (checksumValue >>> (5 * (5 - i))) & 31); return `${hrp}1${[...data, ...checksum].map((value) => CHARSET[value]).join("")}`; }
function decode32(hrp: string, encoded: string, name: string): Uint8Array { if (encoded !== encoded.toLowerCase() || !encoded.startsWith(`${hrp}1`)) throw new Error(`invalid ${name}`); const values = [...encoded.slice(hrp.length + 1)].map((char) => { const value = CHARSET.indexOf(char); if (value < 0) throw new Error(`invalid ${name}`); return value; }); if (polymod([...expand(hrp), ...values]) !== 1) throw new Error("invalid checksum"); const bytes = Uint8Array.from(convertBits(values.slice(0, -6), 5, 8, false)); return bytes; }
/** A plain address is a 32-byte ed25519 key; a multisig one is 0x01 ‖ sha256(policy), see multisig.ts. */
export const MULTISIG_TAG = 0x01;
function checkAddressBytes(bytes: Uint8Array): Uint8Array { if (bytes.length !== 32 && !(bytes.length === 33 && bytes[0] === MULTISIG_TAG)) throw new Error("invalid address length"); return bytes; }
function check32(bytes: Uint8Array, name: string): Uint8Array { if (bytes.length !== 32) throw new Error(`invalid ${name} length`); return bytes; }
export function encodeAddress(publicKey: Uint8Array): string { return encode32(HRP, checkAddressBytes(publicKey)); }
export function decodeAddress(address: string): Uint8Array { return checkAddressBytes(decode32(HRP, address, "address")); }
export function isMultisigAddress(address: string): boolean { return decodeAddress(address).length === 33; }
export function decodeAssetRef(ref: string): Uint8Array { return check32(decode32(ASSET_HRP, ref, "asset ref"), "asset ref"); }
export async function deriveAssetRef(issuer: string, assetId: string): Promise<string> { const pubkey = decodeAddress(issuer), id = new TextEncoder().encode(assetId), domain = new TextEncoder().encode("arxium/asset/v1"), input = new Uint8Array(domain.length + pubkey.length + 1 + id.length); input.set(domain); input.set(pubkey, domain.length); input.set(id, domain.length + pubkey.length + 1); return encode32(ASSET_HRP, new Uint8Array(await crypto.subtle.digest("SHA-256", input))); }
