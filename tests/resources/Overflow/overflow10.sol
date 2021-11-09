pragma solidity 0.8.0;

contract overflow
{
 uint8 public balance = 255;

 function update_balance(uint8 deposit) public
 {
  balance += deposit;
 }

}