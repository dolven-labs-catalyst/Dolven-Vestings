import os
from symbol import with_item
from traceback import print_tb
import pytest

from starkware.starknet.testing.starknet import Starknet
from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash

from merkle_utils import generate_merkle_proof, generate_merkle_root, verify_merkle_proof
import json


@pytest.mark.asyncio
async def test_merkle(capsys):
    array_leaves = []
    with open('user-mock-data.json', 'r') as values_file:
        values = json.load(values_file)
        with capsys.disabled():
            print(values_file, "data for")

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
    
    with open('values.json', 'w') as file:
        json.dump(array_leaves, file)
 
