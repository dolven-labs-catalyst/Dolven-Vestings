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
    split_felt,
    assert_lt_felt,
    assert_le_felt,
    unsigned_div_rem,
    signed_div_rem,
)
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_le,
    uint256_lt,
    uint256_check,
    uint256_eq,
)

from starkware.cairo.common.math_cmp import is_le, is_not_zero, is_nn, is_in_range
from openzeppelin.token.ERC20.interfaces.IERC20 import IERC20
from openzeppelin.access.ownable import Ownable
from openzeppelin.security.pausable import Pausable
from Libraries.DolvenMerkleVerifier import DolvenMerkleVerifier
from openzeppelin.security.reentrancy_guard import ReentrancyGuard
from starkware.cairo.common.hash import hash2
from openzeppelin.security.safemath import SafeUint256

// # Storages

@storage_var
func saleToken() -> (address: felt) {
}

@storage_var
func totalSellAmountToken() -> (totalSellAmountToken: Uint256) {
}

@storage_var
func totalClaimedValue() -> (totalClaimedValue: Uint256) {
}

@storage_var
func MERKLE_ROOT(merkle_root_index : felt) -> (MERKLE_ROOT: felt) {
}

@storage_var
func MERKLE_ROOT_SIZE() -> (size: felt) {
}

// # Structs
// NOTE::Claim percent should be multipled with 100000 while it's adding.

struct roundData {
    roundStartDate: felt,
    roundPercent: Uint256,
}

struct investorData {
    claimRound: felt,
    lastClaimDate: felt,
    claimedValue: Uint256,
}

// # Mappings

@storage_var
func _investorData(address: felt) -> (res: investorData) {
}

@storage_var
func _roundData(index: felt) -> (res: roundData) {
}

@event
func Claimed(user_account: felt, amount: Uint256, timestamp: felt, tcv: Uint256) {
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    _saleToken: felt, _admin: felt
) {
    saleToken.write(_saleToken);
    Ownable.initializer(_admin);
    return ();
}

// #Getters

@view
func _isPaused{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    let (status) = Pausable.is_paused();
    return (status,);
}

@view
func root_size{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    let (size) = MERKLE_ROOT_SIZE.read();
    return (size,);
}

@view
func get_totalClaimedValue{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: Uint256
) {
    let tcv: Uint256 = totalClaimedValue.read();
    return (tcv,);
}

@view
func get_totalSellAmountToken{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: Uint256) {
    let res: Uint256 = totalSellAmountToken.read();
    return (res,);
}

@view
func get_saleToken{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    let token_address: felt = saleToken.read();
    return (token_address,);
}

@view
func get_roundDetails{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    round_index: felt
) -> (res: roundData) {
    let round_details: roundData = _roundData.read(round_index);
    return (round_details,);
}

@view
func get_userDetails{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    user_address: felt
) -> (res: investorData) {
    let user_details: investorData = _investorData.read(user_address);
    return (user_details,);
}

@view
func returnTimeStamp{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    let (res) = get_block_timestamp();
    return (res,);
}

@view
func getMerkleRoot{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(index : felt) -> (
    res: felt
) {
    let response: felt = MERKLE_ROOT.read(index);
    return (response,);
}

@view
func isUserWhitelisted{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    leaf: felt, proof_len: felt, proof: felt*, root_index : felt
) -> (res: felt) {
    alloc_locals;
    let merkle_root: felt = MERKLE_ROOT.read(root_index);
    let res: felt = DolvenMerkleVerifier.verify(leaf, merkle_root, proof_len, proof);
    return (res,);
}

// # External Functions

@external
func claimTokens{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    amounts: felt, proof_len: felt, proof: felt*, random_value: felt, root_index : felt
) {
    alloc_locals;
    ReentrancyGuard._start();
    let (caller) = get_caller_address();
    Pausable.assert_not_paused();
    let root_size : felt = MERKLE_ROOT_SIZE.read();
    assert_not_zero(caller);
    assert_nn_le(root_index, root_size);
    let merkle_root: felt = getMerkleRoot(root_index);
    assert_not_zero(merkle_root);
    let (leaf) = hash_user_data(caller, amounts, random_value);
    let isVerified: felt = DolvenMerkleVerifier.verify(leaf, merkle_root, proof_len, proof);
    with_attr error_message("DolvenVesting::claimTokens verification failed") {
        assert isVerified = 1;
    }
    let investorData_: investorData = _investorData.read(caller);
    let user_claim_round: felt = investorData_.claimRound;
    let round_details: roundData = _roundData.read(user_claim_round);
    assert_not_zero(round_details.roundStartDate);
    let (time) = get_block_timestamp();
    let is_time_due: felt = is_le(round_details.roundStartDate, time);
    with_attr error_message("DolvenVesting::claimTokens round is not started yet") {
        assert is_time_due = 1;
    }

    let amount_as_uint: Uint256 = felt_to_uint256(amounts);
    let multipler_as_uint: Uint256 = Uint256(10000000, 0);
    let cond_one: Uint256 = SafeUint256.mul(round_details.roundPercent, amount_as_uint);
    let (local transferAmount: Uint256, _) = SafeUint256.div_rem(cond_one, multipler_as_uint);
    let total_claimedValue: Uint256 = SafeUint256.add(investorData_.claimedValue, transferAmount);

    let total_entireClaimedValue: Uint256 = totalClaimedValue.read();
    let new_totalClaimedValue: Uint256 = SafeUint256.add(total_entireClaimedValue, transferAmount);

    let total_sell_amount_token: Uint256 = totalSellAmountToken.read();
    let is_total_claimed_less_than_max: felt = uint256_le(
        new_totalClaimedValue, total_sell_amount_token
    );
    with_attr error_message("DolvenVesting::claimTokens all tokens distributed") {
        assert is_total_claimed_less_than_max = 1;
    }

    let is_amount_okay: felt = uint256_le(total_claimedValue, amount_as_uint);
    with_attr error_message("DolvenVesting::claimTokens already you got all your tokens") {
        assert is_amount_okay = 1;
    }
    let _tokenAddress: felt = saleToken.read();
    let (token_transfer_tx: felt) = IERC20.transfer(_tokenAddress, caller, transferAmount);
    with_attr error_message("DolvenVesting::claimTokens payment failed") {
        assert token_transfer_tx = TRUE;
    }
    let new_user_data: investorData = investorData(
        claimRound=investorData_.claimRound + 1, lastClaimDate=time, claimedValue=total_claimedValue
    );
    _investorData.write(caller, new_user_data);
    totalClaimedValue.write(new_totalClaimedValue);
    ReentrancyGuard._end();
    return ();
}

@external
func addNewClaimRound{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    _roundNumber: felt, _roundStartDate: felt, _claimPercent: Uint256
) {
    Ownable.assert_only_owner();
    let new_round_details: roundData = roundData(
        roundStartDate=_roundStartDate, roundPercent=_claimPercent
    );
    _roundData.write(_roundNumber, new_round_details);
    return ();
}

@external
func changePause{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    Ownable.assert_only_owner();
    let current_status: felt = Pausable.is_paused();
    if (current_status == 1) {
        Pausable._unpause();
    } else {
        Pausable._pause();
    }

    return ();
}

@external
func setMerkleRoot{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(root_len : felt, root: felt*, index : felt) {
    Ownable.assert_only_owner();

    if(index == root_len){
    MERKLE_ROOT_SIZE.write(root_len);
    return();
    }

    MERKLE_ROOT.write(index, [root]);
    setMerkleRoot(root_len, root + 1, index + 1);
    return ();
}

@external
func setSaleToken{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    tokenAddress: felt
) {
    Ownable.assert_only_owner();
    saleToken.write(tokenAddress);
    return ();
}

@external
func withdrawTokens{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    Ownable.assert_only_owner();
    let (this) = get_contract_address();
    let (caller) = get_caller_address();
    let _sale_token: felt = saleToken.read();
    let fundAmount: Uint256 = IERC20.balanceOf(_sale_token, this);
    IERC20.transfer(_sale_token, caller, fundAmount);
    return ();
}

@external
func changeTotalSellAmount{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    amount: Uint256
) {
    Ownable.assert_only_owner();
    totalSellAmountToken.write(amount);
    return ();
}

// #Internal Functions

func hash_user_data{pedersen_ptr: HashBuiltin*}(account: felt, amount: felt, random: felt) -> (
    res: felt
) {
    let (res) = hash2{hash_ptr=pedersen_ptr}(account, random);
    let (res) = hash2{hash_ptr=pedersen_ptr}(res, amount);
    return (res=res);
}

func felt_to_uint256{range_check_ptr}(x) -> (uint_x: Uint256) {
    let (high, low) = split_felt(x);
    return (Uint256(low=low, high=high),);
}

func uint256_to_felt{range_check_ptr}(value: Uint256) -> (value: felt) {
    assert_lt_felt(value.high, 2 ** 123);
    return (value.high * (2 ** 128) + value.low,);
}
