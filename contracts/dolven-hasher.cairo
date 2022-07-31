%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    get_caller_address,
    get_contract_address,
    get_block_number,
    get_block_timestamp,
)
from starkware.cairo.common.bool import FALSE, TRUE
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import (
    assert_not_zero,
    assert_not_equal,
    assert_nn_le,
    assert_le,
    unsigned_div_rem,
    signed_div_rem,
)
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_add,
    uint256_sub,
    uint256_le,
    uint256_lt,
    uint256_check,
    uint256_eq,
    uint256_mul,
    uint256_unsigned_div_rem,
)
from starkware.cairo.common.hash import hash2

struct Account:
    member public_key : felt
    member token_a_balance : felt
    member token_b_balance : felt
end

@storage_var
func returnAccount(id : felt) -> (acc : Account):
end

@view
func returnData{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    account_len : felt,
    account : felt*,
    amounts_len : felt,
    amounts : felt*,
    random_len : felt,
    random : felt*,
) -> (result_len : felt, result : felt*):
    assert amounts_len = account_len
    let (result_len, result) = hash_account(
        account_len, account, amounts_len, amounts, random_len, random, 0
    )
    return (result_len, result - result_len)
end

func hash_account{pedersen_ptr : HashBuiltin*}(
    account_len : felt,
    account : felt*,
    amounts_len : felt,
    amounts : felt*,
    random_len : felt,
    random : felt*,
    index : felt,
) -> (hash_len : felt, hash : felt*):
    alloc_locals
    if index == amounts_len:
        let (all_hashes : felt*) = alloc()
        return (0, all_hashes)
    end
    let (res) = hash2{hash_ptr=pedersen_ptr}(account[index], random[index])
    let (res) = hash2{hash_ptr=pedersen_ptr}(res, amounts[index])
    let (length, memory_location) = hash_account(
        account_len, account, amounts_len, amounts, random_len, random, index + 1
    )
    assert [memory_location] = res
    return (length + 1, memory_location + 1)
end

@view
func hash_account_test{pedersen_ptr : HashBuiltin*}(
    account : felt, token_a_balance : felt, random_value : felt
) -> (res : felt):
    let (res) = hash2{hash_ptr=pedersen_ptr}(account, token_a_balance)
    let (res) = hash2{hash_ptr=pedersen_ptr}(res, random_value)
    return (res=res)
end

@external
func writeData{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(id : felt):
    let new_account_data : Account = Account(
        public_key=151515, token_a_balance=2020202, token_b_balance=30303030
    )
    returnAccount.write(id, new_account_data)
    return ()
end
