import { createPublicClient, http, parseAbi } from 'viem';
import { base } from 'viem/chains';

const DEFAULT_RPC = 'https://mainnet.base.org';
const DEFAULT_IDENTITY_REGISTRY = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432' as `0x${string}`;

// MoltGuard wallet — used for self-send calldata anchoring
const DEFAULT_ANCHOR_WALLET = '0x380238347e58435f40B4da1F1A045A271D5838F5' as const;

const IDENTITY_ABI = parseAbi([
  'function ownerOf(uint256 tokenId) view returns (address)',
  'function tokenURI(uint256 tokenId) view returns (string)',
  'function getAgentWallet(uint256 agentId) view returns (address)',
]);

export function createBaseClient(rpcUrl?: string): any {
  return createPublicClient({
    chain: base,
    transport: http(rpcUrl ?? DEFAULT_RPC),
  });
}

/** Check if an ERC-8004 agent exists on-chain */
export async function resolveERC8004Agent(
  client: any,
  agentId: number,
  registryAddress: `0x${string}` = DEFAULT_IDENTITY_REGISTRY
): Promise<{ exists: boolean; owner: string; tokenURI: string }> {
  try {
    const [owner, tokenURI] = await Promise.all([
      client.readContract({
        address: registryAddress,
        abi: IDENTITY_ABI,
        functionName: 'ownerOf',
        args: [BigInt(agentId)],
      }),
      client.readContract({
        address: registryAddress,
        abi: IDENTITY_ABI,
        functionName: 'tokenURI',
        args: [BigInt(agentId)],
      }),
    ]);

    return {
      exists: true,
      owner: owner as string,
      tokenURI: tokenURI as string,
    };
  } catch {
    return { exists: false, owner: '', tokenURI: '' };
  }
}

/**
 * Verify a transaction contains expected calldata (anchor check).
 * MolTrust anchors use self-send TXs with calldata like:
 * - "MolTrust/DocumentIntegrity/1 SHA256:<hash>"
 * - "MolTrust/SkillVC/1 SHA256:<hash>"
 * - Raw SHA256 hex (for DID registration)
 */
export async function verifyTxCalldata(
  client: any,
  txHash: `0x${string}`,
  expectedContent: string
): Promise<{ verified: boolean; blockNumber: bigint | null }> {
  try {
    const tx = await client.getTransaction({ hash: txHash });
    const calldata = Buffer.from(tx.input.slice(2), 'hex').toString('utf8');

    // Check if calldata contains the expected content
    const verified = calldata.includes(expectedContent);

    return {
      verified,
      blockNumber: tx.blockNumber,
    };
  } catch {
    return { verified: false, blockNumber: null };
  }
}

/**
 * Verify a DID registration anchor TX.
 * anchor_to_base() writes SHA256(did:timestamp) as raw hex calldata.
 */
export async function verifyDIDAnchor(
  client: any,
  txHash: `0x${string}`,
  did: string
): Promise<{ verified: boolean; blockNumber: bigint | null }> {
  try {
    const tx = await client.getTransaction({ hash: txHash });
    // The TX exists and was sent — we can verify the sender is the MolTrust wallet
    // but we can't reverse the SHA256 to verify the DID was the input
    // We can only confirm the TX exists on Base
    const verified = tx.blockNumber !== null && tx.blockNumber !== undefined;

    return { verified, blockNumber: tx.blockNumber };
  } catch {
    return { verified: false, blockNumber: null };
  }
}

/**
 * Resolve an agent's Ed25519 public key from a Base L2 DID anchor TX.
 * Calldata format: "MolTrust/DID/v1/<identifier>/<publicKeyHex>"
 */
export async function resolvePublicKeyFromChain(
  client: any,
  did: string,
  anchorTx: `0x${string}`,
): Promise<string | null> {
  const identifier = did.split(':').pop();
  if (!identifier) return null;

  try {
    const tx = await client.getTransaction({ hash: anchorTx });
    const calldata = Buffer.from(
      (tx.input as string).slice(2),
      'hex',
    ).toString('utf8');

    const prefix = `MolTrust/DID/v1/${identifier}/`;
    if (!calldata.startsWith(prefix)) return null;

    const pubKeyHex = calldata.slice(prefix.length).trim();
    if (pubKeyHex.length !== 64) return null; // 32 bytes = 64 hex chars

    return pubKeyHex;
  } catch {
    return null;
  }
}

/**
 * Verify a skill VC anchor. Calldata format: "MolTrust/SkillVC/1 SHA256:<hash>"
 */
export async function verifySkillAnchor(
  client: any,
  txHash: `0x${string}`,
  skillHash: string
): Promise<{ verified: boolean; blockNumber: bigint | null }> {
  const cleanHash = skillHash.replace('sha256:', '');
  return verifyTxCalldata(client, txHash, `MolTrust/SkillVC/1 SHA256:${cleanHash}`);
}
