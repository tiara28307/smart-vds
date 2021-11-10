pragma solidity >=0.7.0 <0.9.0;

contract overflow
{
 uint8 public balance = 255;
 
 function update_balance(uint8 deposit) public
 {
  balance = balance + deposit;
 }
 
}