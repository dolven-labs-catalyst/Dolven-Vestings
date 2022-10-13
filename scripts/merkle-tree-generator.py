from starkware.starknet.testing.starknet import Starknet
from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash

from merkle_utils import generate_merkle_proof, generate_merkle_root
import json

def create_merkle_tree():
    array_leaves = []
    with open('user-mock-data.json', 'r') as values_file:
        values = json.load(values_file)
        print(values, "data for")

    for value in values:
        hash_one = pedersen_hash(int(value["account"]), int(value["random"]))
        hash_res = pedersen_hash(hash_one, int(value["amount"]))
        dict_data = {
            "account": int(value["account"]),
            "random": int(value["random"]),
            "amount": int(value["amount"]),
            "leaf": hash_res
        }
        array_leaves.append(dict_data)


    array = []
    leaf_index = 0
    leaves = []

    for leaf_data in array_leaves:
        leaves.append(leaf_data["leaf"])
    
    for value in leaves:
        if leaf_index < len(leaves):
            proof = generate_merkle_proof(leaves, leaf_index)
            proof_array = []
            for proof_value in proof:
                proof_array.append(hex(proof_value))
            root = hex(generate_merkle_root(leaves))

            # exec_info = await contract.verify(values[leaf_index], root, proof).call()
            #is_valid = exec_info.result.res
            array_values = {
                "user_address": hex(array_leaves[leaf_index]["account"]),
                "user_randomValue": array_leaves[leaf_index]["random"],
                "user_vesting": str(array_leaves[leaf_index]["amount"]),
                "user_proof": proof_array,
                "user_leaf": hex(value)
            }
            array.append(array_values)
            #assert is_valid == 1
            leaf_index += 1
    array.append(root)
    with open('merkle-results.json', 'w') as file:
        json.dump(array, file)


if __name__ == '__main__':
    create_merkle_tree() 
