pragma solidity >=0.7.0 <0.9.0;

contract overflow
{
 uint8 public balance = 255;
 
 function update_balance(uint8 deposit) public
 {
	if((balance + deposit) < (2**8-1))
	{
		balance = balance + deposit;
	}
 }
}