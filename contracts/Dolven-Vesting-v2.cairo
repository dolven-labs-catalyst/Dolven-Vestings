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
from contracts.openzeppelin.token.ERC20.interfaces.IERC20 import IERC20
from contracts.openzeppelin.access.ownable import Ownable
from contracts.openzeppelin.security.pausable import Pausable
from contracts.Interfaces.ITicketManager import ITicketManager
from starkware.cairo.common.hash import hash2
from contracts.openzeppelin.security.reentrancy_guard import ReentrancyGuard

// # Storages

@storage_var
func saleToken() -> (address: felt) {
}

@storage_var
func totalSellAmountToken() -> (totalSellAmountToken: felt) {
}

@storage_var
func totalClaimedValue() -> (totalClaimedValue: felt) {
}

@storage_var
func ticket_manager() -> (address: felt) {
}

@storage_var
func snapshotTime() -> (time: felt) {
}



// # Structs
// NOTE::Claim percent should be multipled with 100000 while it's adding.

struct roundData {
    roundStartDate: felt,
    roundPercent: felt,
}

struct investorData {
    claimRound: felt,
    lastClaimDate: felt,
    claimedValue: felt,
}

// # Mappings

@storage_var
func _investorData(address: felt) -> (res: investorData) {
}

@storage_var
func _roundData(index: felt) -> (res: roundData) {
}

@event
func Claimed(user_account: felt, amount: felt, timestamp: felt, tcv: felt) {
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
func get_totalClaimedValue{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    res: felt
) {
    let tcv: felt = totalClaimedValue.read();
    return (tcv,);
}

@view
func get_totalSellAmountToken{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (res: felt) {
    let res: felt = totalSellAmountToken.read();
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
func user_snapshot_details{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    user_address : felt
) -> (res: felt, ticketAmount : felt, claimAmount : felt) {
    alloc_locals;
    let snTime: felt = snapshotTime.read();
    let _ticketManager : felt = ticket_manager.read();
    let user_votingPower : felt = ITicketManager._checkpointsLookup(_ticketManager, user_address, snTime, 1);
    let voting_supply : felt = ITicketManager._checkpointsLookup(_ticketManager, 0, snTime, 0);
    let is_voting_enough : felt = is_le(1, user_votingPower);

    let total_sell_amount_token: felt = totalSellAmountToken.read();
    let _user_vesting : felt = user_votingPower * total_sell_amount_token;
    let (user_vesting : felt, _) = unsigned_div_rem(_user_vesting, voting_supply);
    
    return (is_voting_enough, user_votingPower, user_vesting);
}


// # External Functions

@external
func setTicketManager{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    manager : felt
) {
    Ownable.assert_only_owner();
    ticket_manager.write(manager);
    return();
}

@external
func setSnapshotTime{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    time : felt
) {
    Ownable.assert_only_owner();
    snapshotTime.write(time);
    return();
}

@external
func _setTicketManager{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    manager : felt
) {
    Ownable.assert_only_owner();
    ticket_manager.write(manager);
    return();
}

@external
func claimTokens{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    ReentrancyGuard._start();
    let (caller) = get_caller_address();
    Pausable.assert_not_paused();
    assert_not_zero(caller);
    let _snapshotTime : felt = snapshotTime.read();
    let _ticketManager : felt = ticket_manager.read();
    let user_votingPower : felt = ITicketManager._checkpointsLookup(_ticketManager, caller, _snapshotTime, 1);
    let is_voting_enough : felt = is_le(1, user_votingPower);
    with_attr error_message("DolvenVesting::claimTokens YOU_HAVE_NO_VESTING") {
        assert is_voting_enough = TRUE;
    }

    let votingSupply : felt = ITicketManager._checkpointsLookup(_ticketManager, caller, _snapshotTime, 0);
    let total_sell_amount_token: felt = totalSellAmountToken.read();
    let _user_vesting : felt = user_votingPower * total_sell_amount_token;
    let (user_vesting : felt, _) = unsigned_div_rem(_user_vesting, votingSupply);


    let investorData_: investorData = _investorData.read(caller);
    let user_claim_round: felt = investorData_.claimRound;
    let round_details: roundData = _roundData.read(user_claim_round);
    assert_not_zero(round_details.roundStartDate);
    let (time) = get_block_timestamp();
    let is_time_due: felt = is_le(round_details.roundStartDate, time);
    with_attr error_message("DolvenVesting::claimTokens round is not started yet") {
        assert is_time_due = 1;
    }

    let cond_one: felt = round_details.roundPercent * user_vesting;
    let (transferAmount: felt, _) = unsigned_div_rem(cond_one, 10000000);
    let transaferAmount_uint : Uint256 = felt_to_uint256(transferAmount);
    let total_claimedValue: felt = investorData_.claimedValue + transferAmount;

    let total_entireClaimedValue: felt = totalClaimedValue.read();
    let new_totalClaimedValue: felt = total_entireClaimedValue + transferAmount;

    let is_total_claimed_less_than_max: felt = is_le(
        new_totalClaimedValue, total_sell_amount_token
    );
    with_attr error_message("DolvenVesting::claimTokens all tokens distributed") {
        assert is_total_claimed_less_than_max = 1;
    }

    let is_amount_okay: felt = is_le(total_claimedValue, user_vesting);
    with_attr error_message("DolvenVesting::claimTokens already you got all your tokens") {
        assert is_amount_okay = 1;
    }
    let _tokenAddress: felt = saleToken.read();
    let (token_transfer_tx: felt) = IERC20.transfer(_tokenAddress, caller, transaferAmount_uint);
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
    _roundNumber: felt, _roundStartDate: felt, _claimPercent: felt
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
    amount: felt
) {
    Ownable.assert_only_owner();
    totalSellAmountToken.write(amount);
    return ();
}

// #Internal Functions


func felt_to_uint256{range_check_ptr}(x) -> (uint_x: Uint256) {
    let (high, low) = split_felt(x);
    return (Uint256(low=low, high=high),);
}

func uint256_to_felt{range_check_ptr}(value: Uint256) -> (value: felt) {
    assert_lt_felt(value.high, 2 ** 123);
    return (value.high * (2 ** 128) + value.low,);
}
