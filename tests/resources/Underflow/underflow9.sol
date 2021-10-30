pragma solidity >=0.7.0 <0.9.0;

contract underflow
{
 function add() public
 {
	for(unit i = 10; i==0; i--)
	{
		data.push(i);
	}
	return data;
 }
}