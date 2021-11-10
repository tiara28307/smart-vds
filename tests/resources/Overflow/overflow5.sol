pragma solidity >=0.7.0 <0.9.0;

contract overflow
{
 uint16 public balance = 65535;
 
 function update_balance(uint16 deposit) public
 {
	if((balance + deposit) < (2**16-1))
	{
		balance = balance + deposit;
	}
 }
}