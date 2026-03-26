import { createHash } from 'node:crypto';

import type { VerifiableCredential, VerificationResult } from './types.js';
import { verifyTxCalldata, verifyDIDAnchor, resolveERC8004Agent } from './chain.js';

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
