pragma solidity 0.7.0;

contract underflow
{
 uint public balance = 0;
 function sub(uint256 deposit) public
 {
  balance -= 10;
 }
}