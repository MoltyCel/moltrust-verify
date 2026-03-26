import type {
  VerifiableCredential,
  VerificationResult,
  VerifierOptions,
  ERC8004AgentInfo,
} from './types.js';
import { createBaseClient, resolveERC8004Agent, verifySkillAnchor, verifyDIDAnchor } from './chain.js';
import { verifyCredential, checkExpiry, computeVCHash, extractDID } from './verifier.js';

export class MolTrustVerifier {
  private client: any;
  private identityRegistry?: `0x${string}`;

  constructor(options: VerifierOptions = {}) {
    this.client = createBaseClient(options.rpcUrl);
    this.identityRegistry = options.identityRegistry;
  }

  /**
   * Verify a W3C Verifiable Credential against Base L2 — no MolTrust API required.
   *
   * @param vc - The Verifiable Credential to verify
   * @param anchorTxHash - Optional Base L2 TX hash where the VC hash was anchored
   */
  async verifyCredential(
    vc: VerifiableCredential,
    anchorTxHash?: `0x${string}`
  ): Promise<VerificationResult> {
    return verifyCredential(vc, this.client, anchorTxHash, this.identityRegistry);
  }

  /**
   * Resolve an ERC-8004 agent from the Base IdentityRegistry.
   * Returns existence, owner, and tokenURI — fully on-chain.
   */
  async resolveERC8004(agentId: number): Promise<ERC8004AgentInfo> {
    const result = await resolveERC8004Agent(this.client, agentId, this.identityRegistry);
    return { agentId, ...result };
  }

  /**
   * Verify a skill VC anchor on Base L2.
   * Checks that the TX calldata contains "MolTrust/SkillVC/1 SHA256:<hash>".
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
