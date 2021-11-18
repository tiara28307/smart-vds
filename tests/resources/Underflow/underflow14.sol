pragma solidity >=0.7.0 <0.9.0;

contract underflow
{
   function withdraw(uint _amount) {
	msg.sender.transfer(_amount);
	if(balances[msg.sender]-_amount > 0)
        {
            balances[msg.sender] -= _amount;
        }
    }
}
