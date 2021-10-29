pragma solidity >=0.7.0 <0.9.0;

contract underflow
{
 uint public deposit = 0;
 function add(uint256 deposit, uint256 tax) public
 {
	if(deposit < 200)
	{
		deposit = deposit - 10;
	}
 }
}