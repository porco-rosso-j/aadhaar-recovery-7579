## Account Recovery Module using AnonAaadhaar

This repo contains the PoC implementation of ERC7579-based recovery module contracts that allow the owner of Aadhaar card ( Indian government-issued biometics card ) to anonymously prove their ownership and carry out social recovery as guardians.

The basic logics is largely based on [zkemail-recovery](https://github.com/zkemail/email-recovery) but guardians are not `EmailAuth.sol` contracts deployed and tied to each guardian address like zkEmail Recovery does. In this module, the recovery manager contract stores uint256-type nullifier that is the hash of a unique and private user identifier extracted from Aadhaar QR code as guardians. In the proof verification, `AnonAadhaarRecoveryManager.sol` simply calls `AnonAadhaar.sol` to verify the proof with `guardian` value passed as a public input.

Since guardians are not a Ethereum account, they generate proofs and send them to relayer to get transactions broadcasted and process recovery. Here, a malicious relayer can't successfully take over the account ownership by modifying the `recoveryCalldata`, e.g. setting new owner as his address in `changeOwner(address)` method instead of the one previous owner sets. This is because the hash of the calldata is bound to proof used as one of the proof generation params ( `signal` ), meaning that the verification would fail if the relayer modified the calldata.

### Anon Aadhaar

[Anon Aadhaar](https://github.com/anon-aadhaar/anon-aadhaar) is a zero-knowledge protocol that allows Aadhaar ID owners to prove their identity in a privacy-preserving way. It provides a set of tools to generate and verify proofs, authenticate users and verify proofs on-chain.

### ERC 7579

_[ERC-7579](https://erc7579.com/) outlines the minimally required interfaces and behavior for modular smart accounts and modules to ensure interoperability across implementations_

### Development

install packages:

```shell
yarn
```

compile contracts:

```shell
yarn/forge build
```

run test:

```shell
yarn/forge test
```

optionally, generate Aadhaar test data, nullifiers and proofs.
Then, you should replace the constant values in test/Inputs with the ones you get from this script.

```
ts-node script/ts/generateTestData.ts
ts-node script/ts/generateProofs.ts
```
