pragma solidity 0.8.0;

contract overflow
{
 uint8 public balance = 255;

 function add(uint8 deposit) public
 {
  balance += deposit;
 }

}