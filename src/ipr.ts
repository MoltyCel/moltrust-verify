/**
 * IPR (Interaction Proof Record) verification — offline via Merkle proof + Base L2.
 */
import { createHash } from 'node:crypto';

export interface MerkleProof {
  root: string;
  leaf: string;
  proof: string[];
  leaf_index: number;
  anchorTx: `0x${string}`;
}

export interface VerifyOutputOptions {
  agentDid: string;
  outputHash: string;
  merkleProof: MerkleProof;
}

export interface VerifyOutputResult {
  verified: boolean;
  agentDid: string;
  outputHash: string;
  anchorBlock?: number;
  anchorTx?: string;
  method: 'merkle-onchain' | 'not-found';
  checkedAt: string;
  reason?: string;
}

function sha256(data: Buffer | string): Buffer {
  return createHash('sha256').update(data).digest();
}

function bufFromHex(hex: string): Buffer {
  return Buffer.from(hex.replace(/^0x/, ''), 'hex');
}

/**
 * Verify a Merkle proof locally (no network).
 * Standard binary Merkle tree — hash pairs from leaf to root.
 */
function verifyMerkleProof(
  leaf: string,
  proof: string[],
  root: string,
  leafIndex: number,
): boolean {
  let hash = bufFromHex(leaf);
  let idx = leafIndex;

  for (const sibling of proof) {
    const sibBuf = bufFromHex(sibling);
    // Left or right based on index parity
    if (idx % 2 === 0) {
      hash = sha256(Buffer.concat([hash, sibBuf]));
    } else {
      hash = sha256(Buffer.concat([sibBuf, hash]));
    }
    idx = Math.floor(idx / 2);
  }

  return hash.toString('hex') === bufFromHex(root).toString('hex');
}

/**
 * Verify an IPR output provenance via Merkle proof + on-chain root.
 *
 * Steps:
 * 1. Verify Merkle proof locally (leaf → root)
 * 2. Fetch anchor TX from Base L2
 * 3. Verify TX calldata contains the Merkle root
 */
export async function verifyOutput(
  options: VerifyOutputOptions,
  client: any,
): Promise<VerifyOutputResult> {
  const { agentDid, outputHash, merkleProof } = options;
  const now = new Date().toISOString();

  // 1. Verify Merkle proof locally
  const proofValid = verifyMerkleProof(
    merkleProof.leaf,
    merkleProof.proof,
    merkleProof.root,
    merkleProof.leaf_index,
  );

  if (!proofValid) {
    return {
      verified: false,
      agentDid,
      outputHash,
      method: 'merkle-onchain',
      reason: 'Merkle proof invalid — leaf does not hash to root',
      checkedAt: now,
    };
  }

  // 2. Fetch anchor TX from chain
  let tx: any;
  try {
    tx = await client.getTransaction({ hash: merkleProof.anchorTx });
  } catch {
    return {
      verified: false,
      agentDid,
      outputHash,
      method: 'not-found',
      reason: 'Anchor TX not found on chain',
      checkedAt: now,
    };
  }

  // 3. Verify calldata contains the Merkle root
  const calldata = Buffer.from(
    (tx.input as string).slice(2),
    'hex',
  ).toString('utf8');

  const rootHex = merkleProof.root.replace(/^0x/, '');
  if (!calldata.includes(rootHex)) {
    return {
      verified: false,
      agentDid,
      outputHash,
      method: 'merkle-onchain',
      reason: 'Anchor TX calldata does not contain Merkle root',
      checkedAt: now,
    };
  }

  return {
    verified: true,
    agentDid,
    outputHash,
    anchorBlock: Number(tx.blockNumber),
    anchorTx: tx.hash,
    method: 'merkle-onchain',
    checkedAt: now,
  };
}
