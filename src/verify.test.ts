import { test, describe } from 'node:test';
import assert from 'node:assert';
import { MolTrustVerifier } from './index.js';
import type { VerifiableCredential } from './types.js';

const verifier = new MolTrustVerifier({ rpcUrl: 'https://mainnet.base.org' });

// Real anchored skill VC data from production
const ANCHORED_SKILL_TX = '0x35929779130718b2e5ca55af45923496accb6ec1d868aef9d968930fb35237a7' as const;
const ANCHORED_SKILL_HASH = 'sha256:ee9fd8343dc0a2e8f1e5cad1d050874cc7abb2291302351d547aa12f999db6f9';

// Real ERC-8004 agent ID (MolTrust agentId: 33553)
const ERC8004_AGENT_ID = 33553;

// TrustScout DID anchor TX
const TRUSTSCOUT_DID_TX = '0x75ea4e77071cb4efb77a9e97a0d7ee49d9914cd01477a37a299fa6bc749c275a' as const;

// TrustScout DID key anchor TX (contains public key in calldata)
const TRUSTSCOUT_KEY_TX = '0xde579d2cdd54a42bb61966ff3eecd9e130af9eac643650a3784b0736acf63d4c' as const;
const TRUSTSCOUT_PUBKEY = '7559b2514a46703465ea558b581ce8dd33121c3b0050a4414769b66a957fa892';

function makeVC(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  const now = new Date();
  const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'AgentTrustCredential'],
    issuer: 'did:web:moltrust.ch',
    issuanceDate: now.toISOString(),
    expirationDate: expires.toISOString(),
    credentialSubject: {
      id: 'did:moltrust:d34ed796a4dc4698',
      trustScore: 85,
    },
    proof: {
      type: 'JsonWebSignature2020',
      created: now.toISOString(),
      verificationMethod: 'did:web:moltrust.ch#moltguard-key-1',
      proofPurpose: 'assertionMethod',
      jws: 'eyJhbGciOiJFZERTQSJ9.test.signature',
    },
    ...overrides,
  };
}

describe('MolTrustVerifier — offline checks', () => {
  test('valid VC passes expiry check', () => {
    const vc = makeVC();
    assert.strictEqual(verifier.isExpired(vc), false);
  });

  test('expired VC fails expiry check', () => {
    const vc = makeVC({
      expirationDate: new Date(Date.now() - 86400000).toISOString(),
    });
    assert.strictEqual(verifier.isExpired(vc), true);
  });

  test('VC without expiry is not expired', () => {
    const vc = makeVC();
    delete (vc as any).expirationDate;
    assert.strictEqual(verifier.isExpired(vc), false);
  });

  test('computeHash returns consistent SHA-256', () => {
    const vc = makeVC();
    const hash1 = verifier.computeHash(vc);
    const hash2 = verifier.computeHash(vc);
    assert.strictEqual(hash1, hash2);
    assert.match(hash1, /^[a-f0-9]{64}$/);
  });

  test('extractDID returns credentialSubject.id', () => {
    const vc = makeVC();
    assert.strictEqual(verifier.extractDID(vc), 'did:moltrust:d34ed796a4dc4698');
  });
});

describe('MolTrustVerifier — on-chain verification', () => {
  test('verifyCredential with no anchor returns partial-onchain', async () => {
    const vc = makeVC();
    const result = await verifier.verifyCredential(vc);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.method, 'partial-onchain');
    assert.strictEqual(result.checks.notExpired, true);
    assert.strictEqual(result.checks.hashAnchored, null);
    assert.strictEqual(result.checks.signatureVerified, null); // Fall C
    assert.ok(result.limitations.length > 0);
  });

  test('expired VC fails verification', async () => {
    const vc = makeVC({
      expirationDate: new Date(Date.now() - 86400000).toISOString(),
    });
    const result = await verifier.verifyCredential(vc);
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.checks.notExpired, false);
  });

  test('signatureVerified is null (Fall C — public key not on-chain)', async () => {
    const vc = makeVC();
    const result = await verifier.verifyCredential(vc);
    assert.strictEqual(result.checks.signatureVerified, null);
    assert.ok(result.limitations.some(l => l.includes('public key not on-chain')));
  });

  test('verifySkillAnchor against real Base TX', async () => {
    const result = await verifier.verifySkillAnchor(ANCHORED_SKILL_TX, ANCHORED_SKILL_HASH);
    assert.strictEqual(result.verified, true);
    assert.ok(result.blockNumber !== null);
    console.log(`  Skill anchor verified at block ${result.blockNumber}`);
  });

  test('verifyDIDAnchor against real TrustScout TX', async () => {
    const result = await verifier.verifyDIDAnchor(TRUSTSCOUT_DID_TX, 'did:moltrust:d34ed796a4dc4698');
    assert.strictEqual(result.verified, true);
    assert.ok(result.blockNumber !== null);
    console.log(`  DID anchor verified at block ${result.blockNumber}`);
  });

  test('resolveERC8004 for MolTrust agent 33553', async () => {
    const agent = await verifier.resolveERC8004(ERC8004_AGENT_ID);
    assert.strictEqual(agent.exists, true);
    assert.strictEqual(agent.agentId, ERC8004_AGENT_ID);
    assert.ok(agent.owner.startsWith('0x'));
    console.log(`  ERC-8004 agent ${ERC8004_AGENT_ID}: owner=${agent.owner}`);
  });

  test('resolveERC8004 for non-existent agent returns exists=false', async () => {
    const agent = await verifier.resolveERC8004(999999999);
    assert.strictEqual(agent.exists, false);
  });
});

describe('MolTrustVerifier — v1.1.0: public key resolution', () => {
  test('resolvePublicKey from TrustScout DID key anchor TX', async () => {
    const key = await verifier.resolvePublicKey(
      'did:moltrust:d34ed796a4dc4698',
      TRUSTSCOUT_KEY_TX,
    );
    assert.strictEqual(key, TRUSTSCOUT_PUBKEY);
    assert.strictEqual(key?.length, 64);
    console.log(`  Resolved public key: ${key}`);
  });

  test('resolvePublicKey returns null for wrong DID', async () => {
    const key = await verifier.resolvePublicKey(
      'did:moltrust:wrong_identifier',
      TRUSTSCOUT_KEY_TX,
    );
    assert.strictEqual(key, null);
  });

  test('resolvePublicKey returns null for non-existent TX', async () => {
    const key = await verifier.resolvePublicKey(
      'did:moltrust:d34ed796a4dc4698',
      '0x' + 'dead'.repeat(16) as `0x${string}`,
    );
    assert.strictEqual(key, null);
  });
});

describe('MolTrustVerifier — v1.1.0: IPR output verification', () => {
  test('verifyOutput rejects invalid merkle proof', async () => {
    const result = await verifier.verifyOutput({
      agentDid: 'did:moltrust:d34ed796a4dc4698',
      outputHash: 'sha256:' + 'aa'.repeat(32),
      merkleProof: {
        root: '0x' + 'dead'.repeat(16),
        leaf: '0x' + 'beef'.repeat(16),
        proof: [],
        leaf_index: 0,
        anchorTx: '0x' + 'dead'.repeat(16) as `0x${string}`,
      },
    });
    assert.strictEqual(result.verified, false);
    assert.ok(result.reason?.includes('Merkle proof invalid') || result.reason?.includes('not found'));
  });

  test('verifyOutput returns correct result shape', async () => {
    const result = await verifier.verifyOutput({
      agentDid: 'did:moltrust:test',
      outputHash: 'sha256:' + 'cc'.repeat(32),
      merkleProof: {
        root: '0x' + 'ab'.repeat(32),
        leaf: '0x' + 'ab'.repeat(32),  // leaf == root (single leaf tree)
        proof: [],
        leaf_index: 0,
        anchorTx: TRUSTSCOUT_DID_TX,  // exists on chain but won't match root
      },
    });
    assert.strictEqual(typeof result.verified, 'boolean');
    assert.strictEqual(typeof result.checkedAt, 'string');
    assert.ok(result.method === 'merkle-onchain' || result.method === 'not-found');
  });
});
