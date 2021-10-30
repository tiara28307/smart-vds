pragma solidity 0.8.0;

contract underflow
{
 uint public balance = 0;
 function add(uint256 deposit, uint256 tax) public
 {
	if(deposit > 0 && balance == 0 && balance-deposit >= 0)
	{
		balance = balance - deposit;
	}
 }
}