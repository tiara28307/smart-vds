pragma solidity ^0.8.5;

contract underflow
{
 uint public balance = 0;
 function sub(uint256 deposit) public
 {
  balance = balance -= deposit;
 }
}