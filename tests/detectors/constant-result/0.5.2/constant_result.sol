pragma solidity >=0.4.5 <=0.5.2;

contract A {
    bool locked;

    modifier noReentrancy() {
        uint8 x = 1;
        require(1 >= 2);// bad
        require(x == x);// bad
        locked = true;
        _;
        locked = false;
    }

    function g2(uint8 y) public returns (bool) {
        return (y == 512); // bad
	}

	function f(uint x) public {
        if (x >= 0) { // bad -- always true
           locked = true;
        }
	}

	function g(uint8 y) public returns (bool) {
        return (y <= 512); // bad
	}

    function h(uint8 y) public returns (bool) {
        return (y < y); // bad
	}
}