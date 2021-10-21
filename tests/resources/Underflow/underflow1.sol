pragma solidity >=0.7.0 <0.9.0;

contract underflow
{
 uint public balance = 0;
 function add(uint256 deposit) public
 {
  balance = balance - deposit;
 }
}