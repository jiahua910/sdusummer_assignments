pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

template Poseidon2Hasher() {
    signal input preimage;
    signal output hash;
    component poseidon = Poseidon(1);  // 输入数量=1
    poseidon.inputs[0] <== preimage;
    hash <== poseidon.out;
}

component main { public [preimage] } = Poseidon2Hasher();