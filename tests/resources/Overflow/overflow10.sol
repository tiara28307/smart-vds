pragma solidity 0.8.9;

contract overflow
{
 uint8 public balance = 255;

 function add(uint8 deposit) public
 {
  balance = balance + deposit;
 }

}