pragma solidity ^0.4.24;

contract ERC20Buggy {

    uint256 public _totalSupply;
    mapping(address => uint) public _balanceOf;
    mapping(address => mapping(address => uint)) public _allowance;
    uint256 c = 0;

    function isContract(address _addr) private returns (bool isContract){
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }


    function transfer(address to, uint256 value) public returns (bool success){
        if (_balanceOf[msg.sender] > value)
            _balanceOf[msg.sender] -= value;
        _balanceOf[to] = _balanceOf[to] + value;
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool success){
        // require(_allowance[msg.sender][from] >= value);
        if (_allowance[msg.sender][from] >= value) {
            _allowance[msg.sender][from] -= value;
            _balanceOf[from] -= value;
            _balanceOf[to] += value;
            return true;
        }
        return false;
    }

    function approve(address _spender, uint256 value) public returns (bool success){
        _allowance[msg.sender][_spender] = value;
        return true;
    }

    function balanceOf(address from) public returns (uint) {
        return _balanceOf[from];
    }

    function allowance(address from, address to) public returns (uint) {
        return _allowance[from][to];
    }

    function totalSupply() public returns (uint){
        return _totalSupply;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    bytes extraDataPre;

    function splitExtra(bytes memory extra) private returns (bytes memory newExtra){
        //extraData rlpcode is storaged from No.32 byte to latest byte.
        //So, the extraData need to reduce 32 bytes at the beginning.
        newExtra = new bytes(extra.length - 32);
        extraDataPre = new bytes(32);
        uint n = 0;
        uint i;
        for (i = 32; i < extra.length; i++) {
            newExtra[n] = extra[i];
            n = n + 1;
        }
        uint m = 0;
        for (i = 0; i < 32; i++) {
            extraDataPre[m] = extra[i];
            m = m + 1;
        }
        return newExtra;
    }

    function testMsgSender() public {
        transfer(msg.sender, 0);
    }
}
