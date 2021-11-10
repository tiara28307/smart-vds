pragma solidity >=0.7.0 <0.9.0;

contract underflow
{
 function withdraw(uint _amount) {
	require(balances[msg.sender] >= _amount);
	msg.sender.call.value(_amount)();
	for(uint i = 10; i==0; i--)
	{
		balances[msg.sender] = i*_amount; 
	}
 }
}

