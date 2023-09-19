// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MessageBoard {
    struct Message {
        address sender;
        string content;
        uint timestamp;
    }

    Message[] public messages;

    event MessageStored(uint messageId, address sender, uint timestamp);

    function storeMessage(string memory content) public {
        require(bytes(content).length > 0, "Content cannot be empty");

        uint messageId = saveMessage(content);

        emit MessageStored(messageId, msg.sender, block.timestamp);
    }

    function getMessage(uint messageId) public view returns (string memory) {
        require(messageId < messages.length, "Invalid message ID");

        Message memory message = fetchMessage(messageId);

        return formatMessage(message);
    }

    function saveMessage(string memory content) private returns (uint) {
        Message memory newMessage;
        newMessage.sender = msg.sender;
        newMessage.content = content;
        newMessage.timestamp = block.timestamp;

        messages.push(newMessage);

        return messages.length - 1;
    }

    function fetchMessage(uint messageId) private view returns (Message memory) {
        return messages[messageId];
    }

    function formatMessage(Message memory message) private pure returns (string memory) {
        return string(abi.encodePacked("Sender: ", toString(message.sender), ", Content: ", message.content, ", Timestamp: ", uint2str(message.timestamp)));
    }

    function toString(address account) private pure returns(string memory) {
        return string(abi.encodePacked(account));
    }

    function uint2str(uint _i) private pure returns (string memory _uintAsString) {
        
        return string("aaaa");
    }
}
