/** Minimal W3C Verifiable Credential shape */
export interface VerifiableCredential {
  '@context': string[];
  type: string[];
  issuer: string | { id: string; name?: string };
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: Record<string, any>;
  proof?: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    jws: string;
  };
}

export interface VerifierOptions {
  /** Base L2 RPC URL. Default: https://mainnet.base.org */
  rpcUrl?: string;
  /** ERC-8004 IdentityRegistry contract address */
  identityRegistry?: `0x${string}`;
  /** MolTrust wallet address for calldata anchor lookups */
  anchorWallet?: `0x${string}`;
}

export interface VerificationResult {
  valid: boolean;
  did: string;
  method: 'onchain' | 'partial-onchain';
  checks: {
    notExpired: boolean;
    hashAnchored: boolean | null;   // null = not checked (no anchor_tx provided)
    erc8004Exists: boolean | null;  // null = not an ERC-8004 DID
    jwsPresent: boolean;
    signatureVerified: boolean | null; // null = public key not on-chain (Fall C)
  };
  limitations: string[];
  checkedAt: string;
}

export interface ERC8004AgentInfo {
  agentId: number;
  owner: string;
  tokenURI: string;
  exists: boolean;
}
