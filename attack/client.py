# client.py (Interactive Inputs with self-contained MD5 Length Extension)
import struct
# hashlib is not used for the attack itself

# --- MD5 Helper Functions (Same as before) ---
def _left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

def _F(x, y, z): return (x & y) | (~x & z)
def _G(x, y, z): return (x & z) | (y & ~z)
def _H(x, y, z): return x ^ y ^ z
def _I(x, y, z): return y ^ (x | ~z)

_S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]

_T = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

def _md5_process_block(block, h0, h1, h2, h3):
    a, b, c, d = h0, h1, h2, h3
    w = struct.unpack('<16I', block)
    for i in range(64):
        if 0 <= i <= 15: f = _F(b, c, d); g = i
        elif 16 <= i <= 31: f = _G(b, c, d); g = (5 * i + 1) % 16
        elif 32 <= i <= 47: f = _H(b, c, d); g = (3 * i + 5) % 16
        elif 48 <= i <= 63: f = _I(b, c, d); g = (7 * i) % 16
        temp = b + _left_rotate((a + f + _T[i] + w[g]) & 0xFFFFFFFF, _S[i])
        a = d; d = c; c = b; b = temp & 0xFFFFFFFF
    return (h0 + a) & 0xFFFFFFFF, (h1 + b) & 0xFFFFFFFF, \
           (h2 + c) & 0xFFFFFFFF, (h3 + d) & 0xFFFFFFFF

def md5_padding(message_byte_len):
    padding = b'\x80'
    bytes_to_add = (56 - (message_byte_len + 1) % 64) % 64
    padding += b'\x00' * bytes_to_add
    original_length_bits = (message_byte_len * 8) & 0xFFFFFFFFFFFFFFFF
    padding += struct.pack('<Q', original_length_bits)
    return padding

def md5_length_extend(secret_len, original_message_bytes, original_hash_hex, data_to_append_bytes):
    h0 = struct.unpack('<I', bytes.fromhex(original_hash_hex[0:8]))[0]
    h1 = struct.unpack('<I', bytes.fromhex(original_hash_hex[8:16]))[0]
    h2 = struct.unpack('<I', bytes.fromhex(original_hash_hex[16:24]))[0]
    h3 = struct.unpack('<I', bytes.fromhex(original_hash_hex[24:32]))[0]

    original_hashed_data_len = secret_len + len(original_message_bytes)
    glue_padding = md5_padding(original_hashed_data_len)
    forged_message_for_server = original_message_bytes + glue_padding + data_to_append_bytes
    
    effective_original_len_for_extension = original_hashed_data_len + len(glue_padding)
    message_for_final_md5_chunk = data_to_append_bytes
    new_total_len_bits_for_final_padding = (effective_original_len_for_extension + len(message_for_final_md5_chunk)) * 8

    padding_for_append_chunk = b'\x80'
    padding_for_append_chunk += b'\x00' * ( (56 - (len(message_for_final_md5_chunk) + 1) % 64) % 64)
    padding_for_append_chunk += struct.pack('<Q', new_total_len_bits_for_final_padding)
    full_chunk_to_process = message_for_final_md5_chunk + padding_for_append_chunk
    
    current_h = [h0, h1, h2, h3]
    for i in range(0, len(full_chunk_to_process), 64):
        block = full_chunk_to_process[i:i+64]
        current_h[0], current_h[1], current_h[2], current_h[3] = \
            _md5_process_block(block, current_h[0], current_h[1], current_h[2], current_h[3])
    
    forged_mac_hex = struct.pack('<IIII', current_h[0], current_h[1], current_h[2], current_h[3]).hex()
    return forged_mac_hex, forged_message_for_server
# --- End of MD5 Helper Functions ---

def perform_attack():
    print("--- Client Attack Setup ---")
    intercepted_message_str = input("Enter the original message string (from server output): ")
    intercepted_mac_str = input("Enter the original MAC (hex string from server output): ")
    
    while True:
        try:
            secret_key_length_str = input("Enter the server's SECRET_KEY length (integer): ")
            secret_key_length = int(secret_key_length_str)
            if secret_key_length < 0:
                print("Secret key length cannot be negative.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter an integer for the secret key length.")

    data_to_append_str = input("Enter the data string to append (e.g., &admin=true): ")
    
    original_message_bytes = intercepted_message_str.encode('utf-8')
    data_to_append_bytes = data_to_append_str.encode('utf-8')

    print("\n=== Attacker (client.py) Side ===")
    print(f"Using Original message string: '{intercepted_message_str}'")
    print(f"Using Original MAC: {intercepted_mac_str}")
    print(f"Using Data to append string: '{data_to_append_str}'")
    print(f"Using Assumed secret key length: {secret_key_length}\n")

    try:
        forged_mac_hex, forged_message_bytes_for_server = md5_length_extend(
            secret_key_length,
            original_message_bytes,
            intercepted_mac_str,
            data_to_append_bytes
        )
        
        print("--- Attack Results ---")
        print(f"Forged MAC (hex): {forged_mac_hex} <--- Note this for server_acc.py")
        print(f"Forged Message for Server (bytes): {forged_message_bytes_for_server} <--- Note this for server_acc.py")
        print(f"Forged Message for Server (hex representation): {forged_message_bytes_for_server.hex()}")

    except Exception as e:
        print(f"Error during length extension attack: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    perform_attack()
