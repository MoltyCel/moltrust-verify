import {
  createHash, verify as cryptoVerify, createPublicKey, ECDH, type KeyObject,
} from 'node:crypto';

import type { VerifiableCredential, VerificationResult } from './types.js';
import { verifyTxCalldata, verifyDIDAnchor, resolveERC8004Agent, resolvePublicKeyFromChain } from './chain.js';

/** Check if a VC has expired */
export function checkExpiry(vc: VerifiableCredential): boolean {
  if (!vc.expirationDate) return true; // no expiry = valid
  return new Date(vc.expirationDate) > new Date();
}

/** Check if a VC's issuance date is not in the future */
export function checkIssuanceDate(vc: VerifiableCredential): boolean {
  return new Date(vc.issuanceDate) <= new Date();
}

/** Compute SHA-256 hash of the credential (excluding proof) */
export function computeVCHash(vc: VerifiableCredential): string {
  const { proof, ...vcWithoutProof } = vc;
  const canonical = JSON.stringify(vcWithoutProof, Object.keys(vcWithoutProof).sort());
  return createHash('sha256').update(canonical).digest('hex');
}

/** Extract DID from credential subject */
export function extractDID(vc: VerifiableCredential): string {
  return vc.credentialSubject.id || '';
}

// SPKI DER prefixes. Appending the raw public key yields a key node:crypto
// can import.
// Ed25519: 32-byte key.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
// P-256 (prime256v1): 65-byte uncompressed SEC1 point (0x04 || X || Y).
const P256_SPKI_PREFIX = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'hex',
);

/** Build an Ed25519 public key from 32 raw bytes given as 64 hex chars. */
function ed25519KeyFromHex(pubKeyHex: string): KeyObject | null {
  if (!/^[0-9a-fA-F]{64}$/.test(pubKeyHex)) return null;
  const derKey = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubKeyHex, 'hex')]);
  return createPublicKey({ key: derKey, format: 'der', type: 'spki' });
}

/**
 * Build a P-256 public key from a SEC1 point given as hex: 33 bytes
 * compressed (66 hex chars) or 65 bytes uncompressed (130 hex chars).
 */
function p256KeyFromHex(pubKeyHex: string): KeyObject | null {
  let uncompressedHex: string;
  if (/^0[23][0-9a-fA-F]{64}$/.test(pubKeyHex)) {
    uncompressedHex = ECDH.convertKey(
      pubKeyHex, 'prime256v1', 'hex', 'hex', 'uncompressed',
    ) as string;
  } else if (/^04[0-9a-fA-F]{128}$/.test(pubKeyHex)) {
    uncompressedHex = pubKeyHex;
  } else {
    return null;
  }
  const derKey = Buffer.concat([P256_SPKI_PREFIX, Buffer.from(uncompressedHex, 'hex')]);
  return createPublicKey({ key: derKey, format: 'der', type: 'spki' });
}

/**
 * Verify a compact JWS against a hex-encoded public key.
 *
 * The algorithm comes from the JWS protected header:
 * - `EdDSA` (or its RFC 9864 alias `Ed25519`): Ed25519, 32-byte key.
 * - `ES256`: ECDSA P-256 with SHA-256. The key is a SEC1 point (compressed
 *   or uncompressed); the signature must be the raw 64-byte r||s pair
 *   (RFC 7518 §3.4), not DER.
 *
 * Any other or missing `alg`, or a key that does not fit the algorithm,
 * fails. There is no fallback to another algorithm.
 */
export function verifyJwsWithPublicKey(jws: string, pubKeyHex: string): boolean {
  try {
    const parts = jws.split('.');
    if (parts.length !== 3) return false;
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (header === null || typeof header !== 'object') return false;
    const alg = header.alg;
    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
    const signature = Buffer.from(parts[2], 'base64url');

    if (alg === 'EdDSA' || alg === 'Ed25519') {
      const publicKey = ed25519KeyFromHex(pubKeyHex);
      if (!publicKey) return false;
      return cryptoVerify(null, signingInput, publicKey, signature);
    }
    if (alg === 'ES256') {
      const publicKey = p256KeyFromHex(pubKeyHex);
      if (!publicKey) return false;
      if (signature.length !== 64) return false;
      return cryptoVerify(
        'sha256',
        signingInput,
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        signature,
      );
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Verify a VC's JWS signature (EdDSA or ES256) using a public key resolved from Base L2.
 * This is the full offline verification path — no MolTrust API needed.
 */
export async function verifyCredentialWithKey(
  vc: VerifiableCredential,
  anchorTx: `0x${string}`,
  client: any,
): Promise<VerificationResult> {
  const did = extractDID(vc);
  const limitations: string[] = [];

  // 1. Expiry check
  const notExpired = checkExpiry(vc) && checkIssuanceDate(vc);

  // 2. JWS presence
  const jwsPresent = !!(vc.proof?.jws && vc.proof.jws.length > 0);

  // 3. Resolve public key from chain
  const pubKeyHex = await resolvePublicKeyFromChain(client, did, anchorTx);

  if (!pubKeyHex) {
    limitations.push('Public key not resolvable from provided anchor TX');
    return {
      valid: notExpired,
      did,
      method: 'partial-onchain',
      checks: {
        notExpired,
        hashAnchored: null,
        erc8004Exists: null,
        jwsPresent,
        signatureVerified: null,
      },
      limitations,
      checkedAt: new Date().toISOString(),
    };
  }

  // 4. Verify the JWS signature (EdDSA or ES256, chosen by the protected header)
  let signatureVerified: boolean | null = null;
  if (jwsPresent && vc.proof?.jws) {
    signatureVerified = verifyJwsWithPublicKey(vc.proof.jws, pubKeyHex);
  }

  const valid = notExpired && (signatureVerified === true);

  return {
    valid,
    did,
    method: 'onchain',
    checks: {
      notExpired,
      hashAnchored: null,
      erc8004Exists: null,
      jwsPresent,
      signatureVerified,
    },
    limitations,
    checkedAt: new Date().toISOString(),
  };
}

/** Extract ERC-8004 agent ID from DID if present */
export function extractERC8004AgentId(vc: VerifiableCredential): number | null {
  const subject = vc.credentialSubject;
  if (subject.erc8004Registered && subject.erc8004AgentId) {
    return Number(subject.erc8004AgentId);
  }
  // Check if the credential itself references an agent ID
  if (typeof subject.agentId === 'number') return subject.agentId;
  return null;
}

/**
 * Verify a VC with maximum offline capability.
 *
 * What can be verified on-chain (without MolTrust API):
 * - VC hash integrity against anchor TX calldata
 * - Expiry and issuance date
 * - ERC-8004 agent existence on Base IdentityRegistry
 * - Anchor TX existence on Base L2
 *
 * What CANNOT be verified offline (Protocol v0.5 limitation):
 * - Ed25519 signature (public key not on-chain)
 * - Revocation status (not on-chain)
 * - Trust score (behavioral data, by design not on-chain)
 */
export async function verifyCredential(
  vc: VerifiableCredential,
  client: any,
  anchorTxHash?: `0x${string}`,
  identityRegistry?: `0x${string}`
): Promise<VerificationResult> {
  const did = extractDID(vc);
  const limitations: string[] = [];

  // 1. Expiry check (always offline)
  const notExpired = checkExpiry(vc) && checkIssuanceDate(vc);

  // 2. JWS presence check
  const jwsPresent = !!(vc.proof?.jws && vc.proof.jws.length > 0);

  // 3. Signature verification — Fall C: public key not on-chain
  const signatureVerified = null;
  limitations.push(
    'Ed25519 public key not on-chain in Protocol v0.5 — signature verification requires MolTrust API (/vc/verify-binding)'
  );

  // 4. Hash anchor check (if TX hash provided)
  let hashAnchored: boolean | null = null;
  if (anchorTxHash) {
    const vcHash = computeVCHash(vc);
    // Try skill VC anchor format first
    const skillResult = await verifyTxCalldata(client, anchorTxHash, vcHash);
    if (skillResult.verified) {
      hashAnchored = true;
    } else {
      // Try DID anchor (TX exists on chain)
      const didResult = await verifyDIDAnchor(client, anchorTxHash, did);
      hashAnchored = didResult.verified;
      if (hashAnchored) {
        limitations.push(
          'DID anchor TX exists on Base but calldata is SHA256(did:timestamp) — cannot reverse-verify DID binding from TX alone'
        );
      }
    }
  } else {
    hashAnchored = null;
    limitations.push('No anchor TX hash provided — on-chain hash integrity not checked');
  }

  // 5. ERC-8004 existence check
  let erc8004Exists: boolean | null = null;
  const agentId = extractERC8004AgentId(vc);
  if (agentId !== null) {
    const agentInfo = await resolveERC8004Agent(client, agentId, identityRegistry);
    erc8004Exists = agentInfo.exists;
  } else {
    erc8004Exists = null;
  }

  // Determine overall validity
  // Valid = not expired + (hash anchored if provided) + (ERC-8004 exists if applicable)
  const anchorOk = hashAnchored === null || hashAnchored === true;
  const erc8004Ok = erc8004Exists === null || erc8004Exists === true;
  const valid = notExpired && anchorOk && erc8004Ok;

  return {
    valid,
    did,
    method: anchorTxHash ? 'onchain' : 'partial-onchain',
    checks: {
      notExpired,
      hashAnchored,
      erc8004Exists,
      jwsPresent,
      signatureVerified,
    },
    limitations,
    checkedAt: new Date().toISOString(),
  };
}
