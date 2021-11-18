pragma solidity >=0.7.0 <0.9.0;

contract underflow
{
 uint public balance = 0;
 function withdraw_balance(uint256 deposit, uint256 tax) public
 {
	if(balance-deposit >= 0)
	{
		balance = balance - deposit;
	}
	balance = balance - deposit;
	if(deposit < 200)
	{
		deposit = deposit - 10;
	}
 }
}