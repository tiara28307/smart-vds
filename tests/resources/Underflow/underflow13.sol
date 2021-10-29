pragma solidity ^0.8.5;

contract underflow
{
 uint public balance = 0;
 function add(uint256 deposit) public
 {
  balance = balance -= deposit;
 }
}