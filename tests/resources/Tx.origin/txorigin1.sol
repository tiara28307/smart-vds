pragma solidity >=0.7.0 <0.9.0;

contract Phishable{
    address public owner;
    constructor (address _owner){
        owner = _owner;
}
function() external payable {}// collect ether
function withdrawAll(address _recipient)public{
require(tx.origin == owner);
        _recipient.transfer(this.balance);
}
}