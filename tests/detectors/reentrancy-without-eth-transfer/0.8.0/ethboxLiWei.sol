// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;


//------------------------------------------------------------------------------------------------------------------
//
// ethbox
//
// ethbox is a smart contract based escrow service. Instead of sending funds from A to B,
// users send funds through ethbox.
//
// Funds are put in "boxes". Each box contains all the relevant data for that transaction.
// Boxes can be secured with a passphrase. Users can request ether or tokens in return
// for their deposit (= OTC trade).
//
// The passphrase gets hashed twice. This is because the smart contract needs to do
// its own hashing so that it cannot be manipulated - But the passphrase shouldn't
// be submitted in clear-text all over the web, so it gets hashed, and the hash of
// that is stored on the smart contract, so it can recognie when it is given the
// correct passphrase.
//
// Depositing funds into contract = create_box(...)
// Retrieving funds from contract = clear_box(...)
//
//------------------------------------------------------------------------------------------------------------------


contract ethbox
{
    // Transaction data
    struct box {
        address         payable sender;
        address         recipient;
        bytes32         pass_hash_hash;
        ERC20Interface  send_token;
        uint            send_value;
        ERC20Interface  request_token;
        uint            request_value;
        uint32          timestamp;
        bool            taken;
    }
    
    address owner;
    box[] boxes;

    // Map box indexes to addresses for easier handling / privacy, so users are shown only their own boxes by the contract
    mapping(address => uint[]) sender_map;
    mapping(address => uint[]) recipient_map;
    
    // Deposit funds into contract
    function create_box(address _recipient, ERC20Interface _send_token, uint _send_value, ERC20Interface _request_token, uint _request_value, bytes32 _pass_hash_hash, uint32 _timestamp) external payable
    {
        // Max 20 outgoing boxes per address, for now
        require(sender_map[msg.sender].length < 20);
        
        // Sending ETH
        if(_send_token == ERC20Interface(address(0)))
            require(msg.value == _send_value);
        // Sending Tokens
        else {
            require(_send_token.balanceOf(msg.sender) >= _send_value);
            _send_token.transferFrom(msg.sender, address(this), _send_value);
        }
        
        box memory new_box;
        new_box.sender          = payable(msg.sender);
        new_box.recipient       = _recipient;
        new_box.pass_hash_hash  = _pass_hash_hash;
        new_box.send_token      = _send_token;
        new_box.send_value      = _send_value;
        new_box.request_token   = _request_token;
        new_box.request_value   = _request_value;
        new_box.timestamp       = _timestamp;
        new_box.taken           = false;
        boxes.push(new_box);
        
        // Save box index to mappings for sender & recipient
        sender_map[msg.sender].push(boxes.length - 1);
        recipient_map[_recipient].push(boxes.length - 1);
    }
    
    
    // Retrieve funds from contract (when sending tokens: have to ask for approval beforehand in web browser interface)
    function clear_box(uint _box_index, bytes32 _pass_hash) external payable
    {
        require((_box_index < boxes.length) && ((msg.sender == boxes[_box_index].sender) || (msg.sender == boxes[_box_index].recipient)) && (!boxes[_box_index].taken));
    
        // If user is recipient, require passphrase and requested ETH / tokens; but not if user is also sender = aborting own transaction
        if((msg.sender == boxes[_box_index].recipient) && (msg.sender != boxes[_box_index].sender)) {
            // Compare stored hash hash to newly computed hash of hash passed by user through web browser interface
            require(boxes[_box_index].pass_hash_hash == keccak256(abi.encodePacked(_pass_hash)));
            
            // Check for balance of requested ETH / tokens, grab tokens if enough
            if(boxes[_box_index].request_value != 0) {
                if(boxes[_box_index].request_token == ERC20Interface(address(0)))
                    require(msg.value == boxes[_box_index].request_value);
                else {
                    require(boxes[_box_index].request_token.balanceOf(msg.sender) >= boxes[_box_index].request_value);
                    boxes[_box_index].request_token.transferFrom(msg.sender, address(this), boxes[_box_index].request_value);
                }
            }
        }
        
        // Transfer sent ETH / tokens to recipient
        if(boxes[_box_index].send_token == ERC20Interface(address(0)))
            payable(msg.sender).transfer(boxes[_box_index].send_value);
        else
            boxes[_box_index].send_token.transfer(msg.sender, boxes[_box_index].send_value);
        
        // Only if user is not sender, aborting his own transaction: transfer requested ETH / tokens to sender
        if((msg.sender == boxes[_box_index].recipient) && (msg.sender != boxes[_box_index].sender)) {
            if(boxes[_box_index].request_token == ERC20Interface(address(0)))
                payable(boxes[_box_index].sender).transfer(boxes[_box_index].request_value);
            else
                boxes[_box_index].request_token.transfer(boxes[_box_index].sender, boxes[_box_index].request_value);
        }
        
        // Mark box as taken, so it can't be taken another time
        boxes[_box_index].taken = true;
        
        // Remove box from sender address => box index mapping
        for(uint8 i = 0; i < sender_map[boxes[_box_index].sender].length; i++) {
            if(sender_map[boxes[_box_index].sender][i] == _box_index) {
                if(i != (sender_map[boxes[_box_index].sender].length - 1))
                    sender_map[boxes[_box_index].sender][i] = sender_map[boxes[_box_index].sender][sender_map[boxes[_box_index].sender].length - 1];
                
                sender_map[boxes[_box_index].sender].pop();
                break;
            }
        }
        
        // Remove box from recipient address => box index mapping
        for(uint8 i = 0; i < recipient_map[boxes[_box_index].recipient].length; i++) {
            if(recipient_map[boxes[_box_index].recipient][i] == _box_index) {
                if(i != (recipient_map[boxes[_box_index].recipient].length - 1))
                    recipient_map[boxes[_box_index].recipient][i] = recipient_map[boxes[_box_index].recipient][recipient_map[boxes[_box_index].recipient].length - 1];
                
                recipient_map[boxes[_box_index].recipient].pop();
                break;
            }
        }
    }
    
    function get_box(uint _box_index) external view returns(box memory)
    {
        // Retrieve single box by index - only for owner of contract and users that are sender or recipient
        require((msg.sender == owner) || (msg.sender == boxes[_box_index].sender) || (msg.sender == boxes[_box_index].recipient));
        return boxes[_box_index];
    }
    
    function get_boxes_out() external view returns(uint[] memory)
    {
        // Retrieve sender address => box index mapping for user
        return sender_map[msg.sender];
    }
    
    function get_boxes_in() external view returns(uint[] memory)
    {
        // Retrieve recipient address => box index mapping for user
        return recipient_map[msg.sender];
    }
    
    function get_all_boxes() external view returns(box[] memory)
    {
        // Retrieve complete boxes array, only for owner
        require(msg.sender == owner);
        return boxes;
    }
    
    function get_num_boxes() external view returns(uint)
    {
        // Retrieve number of boxes, only for owner
        require(msg.sender == owner);
        return boxes.length;
    }
    
    fallback() external payable
    {
        // Don't accept any ETH
        revert();
    }
    
    constructor()
    {
        owner = msg.sender;
    }
}


interface ERC20Interface
{
    // Standard ERC 20 token interface
    
    function totalSupply() external view returns (uint);
    function balanceOf(address tokenOwner) external view returns (uint balance);
    function allowance(address tokenOwner, address spender) external view returns (uint remaining);
    function transfer(address to, uint tokens) external returns (bool success);
    function approve(address spender, uint tokens) external returns (bool success);
    function transferFrom(address from, address to, uint tokens) external returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}