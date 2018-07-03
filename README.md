
# Signature Hashes and Validation

Perhaps the trickiest part of validating a transaction is the process of checking its signatures. A transaction typically has at least one signature per input. If there are multisig outputs being spent, there may be more. As we learned earlier, the ECDSA signature algorithm requires that for each input, we need the public key (P), the signature hash (z), and the Signature (r,s). Once these are determined, the process of verifying the signature is pretty simple.

```python
point = Point.parse(sec)
signature = Signature.parse(der)
point.verify(z, signature)  # True
```

The sec and der formats make getting the P, r and s pretty simple. The hard part is getting the actual signature hash (z). You would think that this would be easy since you can just hash the transaction. But you can't do that since the signature itself is part of the scriptSig and a signature can't sign itself.

Instead, what you need to do is to modify the transaction before actually signing it. That is, you have to compute the z in a very particular way. The procedure is as follows.

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
        # iterate over self.tx_ins
            # create a new TxIn that has a blank script_sig (b'') and add to alt_tx_ins
        # grab the input at the input_index
        # grab the script_pubkey of the input
        # the script_sig of the signing_input should be script_pubkey
        # create an alternate transaction with the modified tx_ins
        # add the hash_type int 4 bytes, little endian
        # get the double_sha256 of the tx serialization
        # convert this to a big-endian integer using int.from_bytes(x, 'big')
        pass
```
