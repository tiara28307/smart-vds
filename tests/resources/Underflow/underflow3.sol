pragma solidity ^0.4.22;

contract Token {

 mapping(address => uint) balances;

 function transfer(address _to, uint _value) public {
   require(balances[msg.sender] - _value >= 0);
   balances[msg.sender] = balances[msg.sender] - _value;
 }
}