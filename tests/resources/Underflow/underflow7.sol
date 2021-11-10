pragma solidity >=0.7.0 <0.9.0;

contract underflow
{
 function transferamount() public
 {
	for(unit i = 10; i>=0; i--)
	{
		balance.push(i);
	}
	msg.sender.transfer(balance);
 }
}