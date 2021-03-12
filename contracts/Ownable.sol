pragma solidity >=0.4.25 <0.7.0;

contract Ownable {
    // state variables
    address owner;

    // modifiers
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    // constructor
    constructor() public{
        owner = msg.sender;
    }
}
