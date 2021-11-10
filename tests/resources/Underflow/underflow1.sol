pragma solidity >=0.7.0 <0.9.0;

contract underflow
{
 uint public balance = 0;
 function withdraw_tax(uint256 tax) public
 {
  balance = balance - tax;
 }
}