- [ZKP pilot project](#zkp-pilot-project)
  - [Logic Flow](#logic-flow)
    - [1. Define the problem statement and circuit](#1-define-the-problem-statement-and-circuit)
    - [2. Set up the proving and verification keys](#2-set-up-the-proving-and-verification-keys)
    - [3. Generate the proof](#3-generate-the-proof)
    - [4. Verify the proof](#4-verify-the-proof)
- [Reference](#reference)


# ZKP pilot project

## Logic Flow

### 1. Define the problem statement and circuit

The first step is to define the problem statement and circuit that the ZKP(e.g. ZK-SNARK) will prove. We want to prove that we know the factors of a certain number without revealing the actual factors themselves.

### 2. Set up the proving and verification keys
We need to set up the proving and verification keys. The proving key is used to generate the proof, while the verification key is used to verify the proof.

### 3. Generate the proof
Once the keys are set up, we can generate the proof using the proving key and the problem statement.

### 4. Verify the proof
Finally, we can verify the proof using the verification key and the problem statement.

Circuit that proves we know the preimage to some hash computed using SHA-256d (calling SHA-256 twice).
```rust
use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    groth16, Circuit, ConstraintSystem, SynthesisError,
};
use bls12_381::Bls12;
use ff::PrimeField;
use pairing::Engine;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Our own SHA-256d gadget. Input and output are in little-endian bit order.
fn sha256d<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    // Flip endianness of each input byte
    let input: Vec<_> = data
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();

    let mid = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;
    let res = sha256(cs.namespace(|| "SHA-256(mid)"), &mid)?;

    // Flip endianness of each output byte
    Ok(res
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect())
}

struct MyCircuit {
    /// The input to SHA-256d we are proving that we know. Set to `None` when we
    /// are verifying a proof (and do not have the witness data).
    preimage: Option<[u8; 80]>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for MyCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Compute the values for the bits of the preimage. If we are verifying a proof,
        // we still need to create the same constraints, so we return an equivalent-size
        // Vec of None (indicating that the value of each bit is unknown).
        let bit_values = if let Some(preimage) = self.preimage {
            preimage
                .into_iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; 80 * 8]
        };
        assert_eq!(bit_values.len(), 80 * 8);

        // Witness the bits of the preimage.
        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            // Allocate each bit.
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b)
            })
            // Convert the AllocatedBits into Booleans (required for the sha256 gadget).
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        // Compute hash = SHA-256d(preimage).
        let hash = sha256d(cs.namespace(|| "SHA-256d(preimage)"), &preimage_bits)?;

        // Expose the vector of 32 boolean variables as compact public inputs.
        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

// Create parameters for our circuit. In a production deployment these would
// be generated securely using a multiparty computation.
let params = {
    let c = MyCircuit { preimage: None };
    groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
};

// Prepare the verification key (for proof verification).
// `params.vk` is proving key
let pvk = groth16::prepare_verifying_key(&params.vk);  

// Pick a preimage and compute its hash.
let preimage = [42; 80];
let hash = Sha256::digest(&Sha256::digest(&preimage));

// Create an instance of our circuit (with the preimage as a witness).
let c = MyCircuit {
    preimage: Some(preimage),
};

// Create a Groth16 proof with our parameters.
let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

// Pack the hash as inputs for proof verification.
let hash_bits = multipack::bytes_to_bits_le(&hash);
let inputs = multipack::compute_multipacking(&hash_bits);

// Check the proof!
assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());

```

# Reference
* [Awesome Zero Knowledge Proofs](https://github.com/matter-labs/awesome-zero-knowledge-proofs)
* [Awesome Crpytography Rust](https://github.com/rust-cc/awesome-cryptography-rust)
