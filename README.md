# @moltrust/verify

Offline W3C Verifiable Credential verification against Base L2 — **no MolTrust API required**.

## Install

```bash
npm install @moltrust/verify
```

## Usage

```typescript
import { MolTrustVerifier } from '@moltrust/verify';

const verifier = new MolTrustVerifier({
  rpcUrl: 'https://mainnet.base.org', // no MolTrust API call
});

// Verify a credential offline
const result = await verifier.verifyCredential(vc, '0xanchorTxHash...');
// { valid: true, method: 'onchain', checks: {...}, limitations: [...] }

// Check ERC-8004 agent existence on Base
const agent = await verifier.resolveERC8004(33553);
// { exists: true, owner: '0x...', tokenURI: '...', agentId: 33553 }

// Verify a skill VC anchor TX
const anchor = await verifier.verifySkillAnchor('0xtxhash', 'sha256:abc...');
// { verified: true, blockNumber: 43748469n }

// Pure offline checks (no RPC needed)
verifier.isExpired(vc);      // boolean
verifier.computeHash(vc);    // SHA-256 hex string
verifier.extractDID(vc);     // 'did:moltrust:...'
```

## What is verified on-chain

| Check | Status | Method |
|---|---|---|
| Expiry / issuance date | Always offline | Date comparison |
| VC hash integrity | On-chain | TX calldata vs SHA-256 |
| ERC-8004 agent existence | On-chain | IdentityRegistry.ownerOf() |
| DID anchor TX existence | On-chain | Base L2 TX lookup |
| Skill VC anchor | On-chain | Calldata: `MolTrust/SkillVC/1 SHA256:<hash>` |
| Ed25519 signature | Not yet | Public key not on-chain (Protocol v0.5) |
| Revocation status | Not yet | Not on-chain (Protocol v0.5) |
| Trust score | By design not | Behavioral data stays off-chain |

## Honest limitations (Protocol v0.5)

Agent Ed25519 public keys are stored in the MolTrust database, not on-chain.
This means **full signature verification still requires the MolTrust API** (via `/vc/verify-binding`).

What works fully offline today:
- VC expiry and issuance date checks
- VC hash integrity against on-chain anchor TX calldata
- ERC-8004 agent existence on Base IdentityRegistry
- Anchor TX existence on Base L2

> Full offline verification including on-chain public key resolution is planned for Protocol v1.0.
> The current version provides partial offline verification with clear documentation of what requires the API.

## API

### `new MolTrustVerifier(options?)`

| Option | Type | Default | Description |
|---|---|---|---|
| rpcUrl | string | https://mainnet.base.org | Base L2 RPC endpoint |
| identityRegistry | 0x... | 0x8004...a432 | ERC-8004 IdentityRegistry |

### `verifier.verifyCredential(vc, anchorTxHash?)`

Returns `VerificationResult`:
```typescript
{
  valid: boolean;
  did: string;
  method: 'onchain' | 'partial-onchain';
  checks: {
    notExpired: boolean;
    hashAnchored: boolean | null;
    erc8004Exists: boolean | null;
    jwsPresent: boolean;
    signatureVerified: boolean | null; // null = not possible offline
  };
  limitations: string[];
  checkedAt: string;
}
```

### `verifier.resolveERC8004(agentId)`
### `verifier.verifySkillAnchor(txHash, skillHash)`
### `verifier.verifyDIDAnchor(txHash, did)`
### `verifier.isExpired(vc)` — no RPC needed
### `verifier.computeHash(vc)` — no RPC needed
### `verifier.extractDID(vc)` — no RPC needed
