import os
from traceback import print_tb
from merkle_utils import generate_merkle_proof, generate_merkle_root
import json


def test_merkle():
    array = []
    leaf_index = 0
    # starknet = await Starknet.empty()
    # contract = await starknet.deploy(source=CONTRACT_FILE)
    with open('values.json', 'r') as values_file:
        values = json.load(values_file)
        print(values[0], "data here")
        leaves = []

    for leaf_data in values:
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
                "user_address": hex(values[leaf_index]["account"]),
                "user_randomValue": values[leaf_index]["random"],
                "user_vesting": values[leaf_index]["amount"],
                "user_proof": proof_array,
                "user_leaf": hex(value)
            }
            array.append(array_values)
            #assert is_valid == 1
            leaf_index += 1
    array.append(root)
    with open('merkle-results.json', 'w') as file:
        json.dump(array, file)


test_merkle()
