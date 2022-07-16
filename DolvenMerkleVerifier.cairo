%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

from Libraries.DolvenMerkle import merkle_verify

namespace DolvenMerkleVerifier:
    @view
    func verify{pedersen_ptr : HashBuiltin*, range_check_ptr}(
        leaf : felt, root : felt, proof_len : felt, proof : felt*
    ) -> (res : felt):
        let (res) = merkle_verify(leaf, root, proof_len, proof)
        return (res)
    end
end
