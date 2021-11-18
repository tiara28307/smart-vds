pragma solidity ^0.8.5;

contract underflow
{
 uint public balance = 0;
 function withdraw_balance(uint256 deposit) public
 {
  balance -= 100;
  msg.sender.transfer(balance);
 }
}