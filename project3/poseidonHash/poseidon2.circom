pragma circom 2.0.0;
include "./node_modules/circomlib/circuits/poseidon.circom";
template Main() { signal input in; signal output out; component p = Poseidon(1); p.inputs[0] <== in; out <== p.out; } 
component main = Main();