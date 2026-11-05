import * as bitcoinjs from 'bitcoinjs-lib';
import * as types from 'bitcoinjs-lib/src/types';
import { payments, ScriptSignature } from 'bitcoinjs-lib';
const typeforce = require('typeforce');

import { Network } from '../..';
import {
  getDefaultConsensusBranchIdForVersion,
  getDefaultVersionGroupIdForVersion,
  ZcashNetwork,
  ZcashTransaction,
} from './ZcashTransaction';
import { UtxoTransactionBuilder } from '../UtxoTransactionBuilder';
import { toOutputScript } from './address';
import { ZcashPrevOutput } from './hashZip0244';
import { ecc as eccLib } from '../../noble_ecc';
import { fixMultisigOrder, Signer, TxbSignArg } from '../../transaction_builder';

export class ZcashTransactionBuilder<TNumber extends number | bigint = number> extends UtxoTransactionBuilder<
  TNumber,
  ZcashTransaction<TNumber>
> {
  constructor(network: ZcashNetwork) {
    super(network);
  }

  protected createInitialTransaction(network: Network): ZcashTransaction<TNumber> {
    return new ZcashTransaction<TNumber>(network as ZcashNetwork);
  }

  static fromTransaction<TNumber extends number | bigint = number>(
    transaction: ZcashTransaction<TNumber>,
    network?: Network,
    prevOutput?: bitcoinjs.TxOutput<TNumber>[]
  ): ZcashTransactionBuilder<TNumber> {
    const txb = new ZcashTransactionBuilder<TNumber>(transaction.network);

    // Copy transaction fields
    txb.setVersion(transaction.version, !!transaction.overwintered);
    txb.setLockTime(transaction.locktime);

    // Copy Zcash overwinter fields. Omitted if the transaction builder is not for Zcash.
    if (txb.tx.isOverwinterCompatible()) {
      txb.setVersionGroupId(transaction.versionGroupId);
      txb.setExpiryHeight(transaction.expiryHeight);
    }

    txb.setConsensusBranchId(transaction.consensusBranchId);

    // Copy outputs (done first to avoid signature invalidation)
    transaction.outs.forEach(function (txOut) {
      txb.addOutput(txOut.script, txOut.value);
    });

    // Copy inputs
    transaction.ins.forEach(function (txIn) {
      (txb as any).__addInputUnsafe(txIn.hash, txIn.index, {
        sequence: txIn.sequence,
        script: txIn.script,
        witness: txIn.witness,
        value: (txIn as any).value,
      });
    });

    const prevOutputs = prevOutput ?? transaction.prevOutputs;
    if (prevOutputs) {
      // Same as UtxoTransactionBuilder.fromTransaction: remember each input's value and
      // scriptPubKey so sign() can be called without repeating them.
      const txbInputs = (txb as any).__INPUTS;
      if (prevOutputs.length !== txbInputs.length) {
        throw new Error(`prevOuts must match txbInput length`);
      }
      prevOutputs.forEach((o, i) => {
        txbInputs[i].value = o.value;
        if (!txbInputs[i].prevOutScript) {
          txbInputs[i].prevOutScript = o.script;
        }
      });
      txb.setPrevOutputs(prevOutputs);
    } else if (txb.tx.version === 5 && txb.hasSignatures()) {
      // Partially signed multisig inputs are parsed with their signatures in scriptSig order,
      // not pubkey order. Aligning them needs the sighash, which for v5 needs the prevouts, so
      // that happens in setPrevOutputs() once the caller provides them.
      txb.multisigOrderPending = true;
    }

    return txb;
  }

  /** Set when multisig signatures parsed from a v5 scriptSig still need aligning to pubkeys. */
  private multisigOrderPending = false;

  /**
   * Set the coins spent by the transparent inputs (one entry per input, in input order): their
   * value and scriptPubKey. Required before signing a v5 transaction with more than one input:
   * the ZIP-244 signature digest commits to every input's value and scriptPubKey. Must be called
   * after all inputs have been added.
   *
   * Prevouts are not serialized, so a partially signed transaction that was round-tripped
   * through its wire encoding has none. Setting them then is allowed, but every signature
   * already present is re-verified against the new prevouts, so a wrong value cannot silently
   * invalidate an earlier signing round. Changing already known prevouts under existing
   * signatures is refused outright.
   */
  setPrevOutputs(prevOutputs: ZcashPrevOutput<TNumber>[]): void {
    const current = this.tx.prevOutputs;
    if (current && this.hasSignatures()) {
      const same =
        current.length === prevOutputs.length &&
        current.every((p, i) => BigInt(p.value) === BigInt(prevOutputs[i].value) && p.script.equals(prevOutputs[i].script));
      if (!same) {
        throw new Error(`Changing prevOutputs for a partially signed transaction would invalidate signatures`);
      }
      return;
    }
    this.tx.setPrevOutputs(prevOutputs);
    if (this.tx.version === 5 && this.hasSignatures()) {
      try {
        this.alignAndVerifyExistingSignatures();
      } catch (e) {
        this.tx.prevOutputs = undefined;
        throw e;
      }
    }
  }

  /**
   * Checks every signature already present on the inputs against the ZIP-244 digest computed
   * from the current prevouts. Multisig signatures parsed from a scriptSig are first matched to
   * their pubkeys (bitcoinjs' TransactionBuilder.fromTransaction does the same for v4); a
   * signature that matches no pubkey means the prevouts are wrong. Only ECDSA (p2pkh /
   * p2sh-p2ms) inputs exist for Zcash.
   */
  private alignAndVerifyExistingSignatures(): void {
    const inputs = (this as any).__INPUTS as Array<{
      signatures?: (Buffer | undefined)[];
      pubkeys?: (Buffer | undefined)[];
      redeemScript?: Buffer;
      redeemScriptType?: string;
    }>;
    const prevOutputs = this.tx.prevOutputs ?? [];
    inputs.forEach((input, vin) => {
      if (!input.signatures || !input.pubkeys) {
        return;
      }
      const prevOutput = prevOutputs[vin];
      if (!prevOutput) {
        throw new Error(`no prevOutput for input ${vin}`);
      }
      const presentBefore = input.signatures.filter((s) => !!s).length;
      if (this.multisigOrderPending) {
        fixMultisigOrder(input as any, this.tx, vin, prevOutputs as bitcoinjs.TxOutput<TNumber>[]);
        const presentAfter = (input.signatures ?? []).filter((s) => !!s).length;
        if (presentAfter !== presentBefore) {
          throw new Error(`existing signature on input ${vin} does not verify against the given prevOutputs`);
        }
      }
      input.signatures.forEach((signatureBuffer, i) => {
        const pubkey = input.pubkeys?.[i];
        if (!signatureBuffer || !pubkey) {
          return;
        }
        const { signature, hashType } = ScriptSignature.decode(signatureBuffer);
        const hash = this.tx.hashForSignatureByNetwork(vin, prevOutput.script, prevOutput.value, hashType);
        if (!eccLib.verify(hash, pubkey, signature, true)) {
          throw new Error(`existing signature on input ${vin} does not verify against the given prevOutputs`);
        }
      });
    });
    this.multisigOrderPending = false;
  }

  /**
   * Before signing a v5 transaction, make sure every input's prevout is known. They can come from
   * an explicit setPrevOutputs() call, from addInput(hash, index, sequence, prevOutScript, value),
   * or from fromTransaction(..., prevOutputs). The input being signed now may also derive its
   * scriptPubKey from the redeemScript (P2SH) or the signing key (P2PKH), and its value from the
   * sign() argument.
   *
   * Unlike v4, a multi-input v5 transaction cannot be signed input by input with only each
   * input's own value: the ZIP-244 digest commits to every input's value and scriptPubKey, so all
   * of them must be known before the first signature.
   */
  sign(
    signParams: number | TxbSignArg<TNumber>,
    keyPair?: Signer,
    redeemScript?: Buffer,
    hashType?: number,
    witnessValue?: TNumber,
    witnessScript?: Buffer
  ): void {
    // Also for a single input: without prevouts the transaction would treat the scriptCode as the
    // scriptPubKey, which is wrong for P2SH (scriptCode = redeemScript).
    if (this.tx.version === 5 && !this.tx.prevOutputs) {
      const vin = typeof signParams === 'number' ? signParams : signParams.vin;
      const value = typeof signParams === 'number' ? witnessValue : signParams.witnessValue;
      const signer = typeof signParams === 'number' ? keyPair : signParams.keyPair;
      const redeem = typeof signParams === 'number' ? redeemScript : signParams.redeemScript;
      const prevOutputs = this.collectPrevOutputs(vin, value, signer, redeem);
      if (prevOutputs) {
        this.setPrevOutputs(prevOutputs);
      }
      // Otherwise fall through: the transaction will throw a clear "call setPrevOutputs()" error.
    }
    super.sign(signParams, keyPair, redeemScript, hashType, witnessValue, witnessScript);
  }

  private collectPrevOutputs(
    vin: number,
    value: TNumber | undefined,
    keyPair: Signer | undefined,
    redeemScript: Buffer | undefined
  ): ZcashPrevOutput<TNumber>[] | undefined {
    const inputs = (this as any).__INPUTS as Array<{ value?: TNumber; prevOutScript?: Buffer }>;
    const prevOutputs: ZcashPrevOutput<TNumber>[] = [];
    for (let i = 0; i < inputs.length; i++) {
      let script = inputs[i].prevOutScript;
      let v = inputs[i].value;
      if (i === vin) {
        v = value ?? v;
        if (!script && redeemScript) {
          script = payments.p2sh({ redeem: { output: redeemScript }, network: this.network as Network }).output;
        }
        if (!script && keyPair) {
          script = payments.p2pkh({ pubkey: keyPair.publicKey, network: this.network as Network }).output;
        }
      }
      if (!script || v === undefined) {
        return undefined;
      }
      prevOutputs.push({ value: v, script });
    }
    return prevOutputs;
  }

  setVersion(version: number, overwinter = true): void {
    typeforce(types.UInt32, version);
    this.tx.overwintered = overwinter ? 1 : 0;
    this.tx.version = version;
  }

  setDefaultsForVersion(network: Network, version: number): void {
    switch (version) {
      case 4:
      case ZcashTransaction.VERSION4_BRANCH_CANOPY:
      case ZcashTransaction.VERSION4_BRANCH_NU5:
      case ZcashTransaction.VERSION4_BRANCH_NU6:
        this.setVersion(4);
        break;
      case 5:
      case ZcashTransaction.VERSION5_BRANCH_NU5:
      case ZcashTransaction.VERSION5_BRANCH_NU6:
      case ZcashTransaction.VERSION5_BRANCH_NU7:
        this.setVersion(5);
        break;
      default:
        throw new Error(`invalid version ${version}`);
    }

    this.tx.versionGroupId = getDefaultVersionGroupIdForVersion(version);
    this.tx.consensusBranchId = getDefaultConsensusBranchIdForVersion(network, version);
  }

  private hasSignatures(): boolean {
    return (this as any).__INPUTS.some(function (input: { signatures: unknown }) {
      return input.signatures !== undefined;
    });
  }

  private setPropertyCheckSignatures(propName: keyof ZcashTransaction<TNumber>, value: unknown) {
    if (this.tx[propName] === value) {
      return;
    }
    if (this.hasSignatures()) {
      throw new Error(`Changing property ${propName} for a partially signed transaction would invalidate signatures`);
    }
    this.tx[propName] = value as any;
  }

  setConsensusBranchId(consensusBranchId: number): void {
    typeforce(types.UInt32, consensusBranchId);
    this.setPropertyCheckSignatures('consensusBranchId', consensusBranchId);
  }

  setVersionGroupId(versionGroupId: number): void {
    typeforce(types.UInt32, versionGroupId);
    this.setPropertyCheckSignatures('versionGroupId', versionGroupId);
  }

  setExpiryHeight(expiryHeight: number): void {
    typeforce(types.UInt32, expiryHeight);
    this.setPropertyCheckSignatures('expiryHeight', expiryHeight);
  }

  build(): ZcashTransaction<TNumber> {
    return super.build() as ZcashTransaction<TNumber>;
  }

  buildIncomplete(): ZcashTransaction<TNumber> {
    return super.buildIncomplete() as ZcashTransaction<TNumber>;
  }

  addOutput(scriptPubKey: string | Buffer, value: TNumber): number {
    // Attempt to get a script if it's a base58 or bech32 address string
    if (typeof scriptPubKey === 'string') {
      scriptPubKey = toOutputScript(scriptPubKey, this.network as Network);
    }

    return super.addOutput(scriptPubKey, value);
  }
}
