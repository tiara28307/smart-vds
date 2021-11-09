pragma solidity 0.8.0;

contract underflow
{
 function withdraw(uint _amount) {
	msg.sender.transfer(_amount);
	if(deposit > 0 && balance == 0 && balances[msg.sender] >= 0)
	{
		balances[msg.sender] = balances[msg.sender] - _amount;
	}
 }	
}