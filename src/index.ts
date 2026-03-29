import type {
  VerifiableCredential,
  VerificationResult,
  VerifierOptions,
  ERC8004AgentInfo,
} from './types.js';
import { createBaseClient, resolveERC8004Agent, verifySkillAnchor, verifyDIDAnchor, resolvePublicKeyFromChain } from './chain.js';
import { verifyCredential, verifyCredentialWithKey, checkExpiry, computeVCHash, extractDID } from './verifier.js';
import { verifyOutput } from './ipr.js';
import type { VerifyOutputOptions, VerifyOutputResult, MerkleProof } from './ipr.js';

export class MolTrustVerifier {
  private client: any;
  private identityRegistry?: `0x${string}`;

  constructor(options: VerifierOptions = {}) {
    this.client = createBaseClient(options.rpcUrl);
    this.identityRegistry = options.identityRegistry;
  }

  /**
   * Verify a W3C Verifiable Credential against Base L2 — no MolTrust API required.
   */
  async verifyCredential(
    vc: VerifiableCredential,
    anchorTxHash?: `0x${string}`
  ): Promise<VerificationResult> {
    return verifyCredential(vc, this.client, anchorTxHash, this.identityRegistry);
  }

  /**
   * Verify a VC with full Ed25519 signature check using on-chain public key.
   * Requires the DID anchor TX that contains the public key.
   */
  async verifyCredentialWithKey(
    vc: VerifiableCredential,
    anchorTx: `0x${string}`,
  ): Promise<VerificationResult> {
    return verifyCredentialWithKey(vc, anchorTx, this.client);
  }

  /**
   * Verify an IPR output provenance via Merkle proof + on-chain root.
   * Fully offline — only needs Base L2 RPC.
   */
  async verifyOutput(options: VerifyOutputOptions): Promise<VerifyOutputResult> {
    return verifyOutput(options, this.client);
  }

  /**
   * Resolve an agent's Ed25519 public key from a Base L2 DID anchor TX.
   * Returns 64-char hex string or null.
   */
  async resolvePublicKey(
    did: string,
    anchorTx: `0x${string}`,
  ): Promise<string | null> {
    return resolvePublicKeyFromChain(this.client, did, anchorTx);
  }

  /**
   * Resolve an ERC-8004 agent from the Base IdentityRegistry.
   */
  async resolveERC8004(agentId: number): Promise<ERC8004AgentInfo> {
    const result = await resolveERC8004Agent(this.client, agentId, this.identityRegistry);
    return { agentId, ...result };
  }

  /**
   * Verify a skill VC anchor on Base L2.
   */
  async verifySkillAnchor(txHash: `0x${string}`, skillHash: string) {
    return verifySkillAnchor(this.client, txHash, skillHash);
  }

  /**
   * Verify a DID registration anchor TX exists on Base L2.
   */
  async verifyDIDAnchor(txHash: `0x${string}`, did: string) {
    return verifyDIDAnchor(this.client, txHash, did);
  }

  /**
   * Check if a VC has expired (offline, no chain call needed).
   */
  isExpired(vc: VerifiableCredential): boolean {
    return !checkExpiry(vc);
  }

  /**
   * Compute the SHA-256 hash of a credential (excluding proof).
   */
  computeHash(vc: VerifiableCredential): string {
    return computeVCHash(vc);
  }

  /**
   * Extract the DID from a credential's subject.
   */
  extractDID(vc: VerifiableCredential): string {
    return extractDID(vc);
  }
}

export type {
  VerifiableCredential,
  VerificationResult,
  VerifierOptions,
  ERC8004AgentInfo,
} from './types.js';

export type {
  VerifyOutputOptions,
  VerifyOutputResult,
  MerkleProof,
} from './ipr.js';
