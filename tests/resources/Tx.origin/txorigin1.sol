pragma solidity 0.6.0;

contract Phishable{
    address public owner;
    uint256 balance = 100;
    constructor (address _owner) public {
        owner = _owner;
    }

    function addToBalance(uint256 amount) public {
        if (msg.sender == tx.origin){
            balance += amount;
        }
    }

    function withdrawAll(uint256 amount) public{
        require(tx.origin == owner);
        balance -= amount;
    }
}