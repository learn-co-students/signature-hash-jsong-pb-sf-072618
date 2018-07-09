
# Signature Hashes and Validation

Perhaps the trickiest part of validating a transaction is the process of checking its signatures. A transaction typically has at least one signature per input. If there are multisig outputs being spent, there may be more. As we learned earlier, the ECDSA signature algorithm requires that for each input, we need the public key (P), the signature hash (z), and the Signature (r,s). Once these are determined, the process of verifying the signature is pretty simple.

```python
point = Point.parse(sec)
signature = Signature.parse(der)
point.verify(z, signature)  # True
```

The sec and der formats make getting the P, r and s pretty simple. The hard part is getting the actual signature hash (z). You would think that this would be easy since you can just hash the transaction. But you can't do that since the signature itself is part of the scriptSig and a signature can't sign itself.

Instead, what you need to do is to modify the transaction before actually signing it. That is, you have to compute the z in a very particular way. The procedure is as follows.


```python
# double_sha256 example to get z

from helper import double_sha256

modified_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000001976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88acfeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac1943060001000000')
h = double_sha256(modified_tx)
z = int.from_bytes(h, 'big')
print(hex(z))
```

### Test Driven Exercise


```python
from io import BytesIO
from helper import (
    SIGHASH_ALL,
    int_to_little_endian,
    double_sha256
)
from tx import Tx, TxIn


class Tx(Tx):


    def sig_hash(self, input_index, hash_type):
        '''Returns the integer representation of the hash that needs to get
        signed for index input_index'''
        # create a new set of tx_ins (alt_tx_ins)
        alt_tx_ins = []
        # iterate over self.tx_ins
        for tx_in in self.tx_ins:
            # create a new TxIn that has a blank script_sig (b'') and add to alt_tx_ins
            alt_tx_ins.append(TxIn(
                prev_tx=tx_in.prev_tx,
                prev_index=tx_in.prev_index,
                script_sig=b'',
                sequence=tx_in.sequence,
            ))
        # grab the input at the input_index
        signing_input = alt_tx_ins[input_index]
        # grab the script_pubkey of the input
        script_pubkey = signing_input.script_pubkey(self.testnet)
        # the script_sig of the signing_input should be script_pubkey
        signing_input.script_sig = script_pubkey
        # create an alternate transaction with the modified tx_ins
        alt_tx = self.__class__(
            version=self.version,
            tx_ins=alt_tx_ins,
            tx_outs=self.tx_outs,
            locktime=self.locktime)
        # add the hash_type int 4 bytes, little endian
        result = alt_tx.serialize() + int_to_little_endian(hash_type, 4)
        # get the double_sha256 of the tx serialization
        s256 = double_sha256(result)
        # convert this to a big-endian integer using int.from_bytes(x, 'big')
        return int.from_bytes(s256, 'big')
```
