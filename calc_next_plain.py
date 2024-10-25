from Crypto.Util.Padding import pad
from binascii import unhexlify, hexlify

message = input("Please plaintext: ")
IV = input("IV:")
nextIV = input("Next IV:")

block_size = 16
padded_message = pad(message.encode(), block_size)
padded_hex = hexlify(padded_message)

# Convert hex strings to bytes
padded_message_bytes = unhexlify(padded_hex)
hex1_bytes = unhexlify(IV)
hex2_bytes = unhexlify(nextIV)

# Step 3: XOR the values
result = bytearray()
for i in range(len(padded_message_bytes)):
    result.append(padded_message_bytes[i] ^ hex1_bytes[i] ^ hex2_bytes[i])

# Step 4: Print the result as hex
result_hex = hexlify(result).decode()
print("Adjusted Plaintext P' :", result_hex)

