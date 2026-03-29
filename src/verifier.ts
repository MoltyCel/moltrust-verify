import { createHash, verify as cryptoVerify, createPublicKey } from 'node:crypto';

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

/**
 * Verify a VC's Ed25519 signature using a public key resolved from Base L2.
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

  // 4. Verify Ed25519 signature
  let signatureVerified: boolean | null = null;
  if (jwsPresent && vc.proof?.jws) {
    try {
      const jws = vc.proof.jws;
      const parts = jws.split('.');
      if (parts.length === 3) {
        const signingInput = `${parts[0]}.${parts[1]}`;
        const signature = Buffer.from(parts[2], 'base64url');
        const pubKeyBytes = Buffer.from(pubKeyHex, 'hex');

        // Build Ed25519 public key in DER format for Node crypto
        // Ed25519 public key DER prefix: 302a300506032b6570032100
        const derPrefix = Buffer.from('302a300506032b6570032100', 'hex');
        const derKey = Buffer.concat([derPrefix, pubKeyBytes]);
        const publicKey = createPublicKey({ key: derKey, format: 'der', type: 'spki' });

        signatureVerified = cryptoVerify(
          null,
          Buffer.from(signingInput),
          publicKey,
          signature,
        );
      }
    } catch {
      signatureVerified = false;
    }
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
