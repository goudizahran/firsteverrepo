# Intro To Programming Coursework 1 
# Steganography Program 
# Goudi Zahran 202400725 



# marker generation 
def generate_marker(seed, length=5):
    character_library = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"

    # simple deterministic hash, sum of character ordinal values
    seed_hash = sum(ord(char) for char in seed)
    
    marker = ""
    current_value = seed_hash
    
    for i in range(length):
        # use modulus to cycle through the character pool
        index = current_value % len(character_library)
        marker += character_library[index]
        
        # simple modification for the next character (LCG)
        current_value = (current_value * 7 + 1)
        
    return "$" + marker 




# basic file functions 



def open_image_file(filename):
# attempt to open file and return its bytes
    try:
        with open(filename, "rb") as f:
            return bytearray(f.read())
    except:
        return None 



def save_image_file(filename, data):
# save modified bytes to a new BMP file 
    with open(filename, "wb") as f:
        f.write(data)



def is_bmp_file(data):
# check BMP signature (first two bytes 'BM'), making sure this is a BMP image 
    return data is not None and len(data) >= 2 and data[0:2] == b'BM'



def get_pixel_data_offset(data):
# byte offset where pixel array starts (from BMP header), this is done to determine where the pixels begin, clarifies where to hide the message and ensures the header is intact 
    return int.from_bytes(data[10:14], byteorder='little')


def get_bits_per_pixel(data):
# return bits per pixel value from BMP header (for simple validation), determines whether the image is grey-scale or color (RGB)
    return int.from_bytes(data[28:30], byteorder='little')



# encoding funtions 



def can_image_fit_message(data, message):
# simple check whether there are enough bytes in the image to hide the message 
    pixel_start = get_pixel_data_offset(data)
    bpp = get_bits_per_pixel(data)
    bytes_per_pixel = bpp // 8
    num_pixels = (len(data) - pixel_start) // bytes_per_pixel
    available_bits = num_pixels * bytes_per_pixel
    required_bits = len(message) * 8
    return required_bits <= available_bits



def encode_message_into_pixels(data, message):
# write message bits into LSB of image bytes starting at pixel data offset
    pixel_start = get_pixel_data_offset(data)

# convert message to bit list
    msg_bits = []
    for ch in message:
        bits = format(ord(ch), "08b")
        for b in bits:
            msg_bits.append(int(b))

# write bits into LSBs
    idx = pixel_start
    for bit in msg_bits:
        data[idx] = (data[idx] & 0xFE) | bit
        idx += 1

    return data


def hide_mode():
    print("\n--- HIDE (encode) MODE ---")

    # --- loop until a valid BMP file is opened ---
    while True:
        filename = input("enter BMP filename to hide message in: ").strip()
        data = open_image_file(filename)

        if data is None:
            print("file not found. please check filename and try again.")
            continue

        if not is_bmp_file(data):
            print("error: file is not a BMP image. try a different file.")
            continue

        bpp = get_bits_per_pixel(data)
        if bpp not in (8, 24):
            print("error: unsupported bits-per-pixel value:", bpp)
            continue

        # success means we can break the loop
        break

    pixel_start = get_pixel_data_offset(data)
    # --- get the seed (password) and generate markers ---
    secret_key = input("please enter a password for the message: ").strip()
    # generate unique start and end markers based on the key
    start_marker = generate_marker(secret_key + "alpha")
    end_marker = generate_marker(secret_key + "omega")

    # --- loop until the message fits inside the image ---
    while True:
        user_message = input("please enter your secret message: ")
        full_message = start_marker + user_message + end_marker

        if can_image_fit_message(data, full_message):
            break
        else:
            print("error: message too long for this image.")
            print("please enter a shorter message.\n")

    # encode now that everything is valid
    new_data = encode_message_into_pixels(data, full_message)

    outname = input("enter output filename for new image (e.g., new.bmp): ").strip()
    save_image_file(outname, new_data)
    print("message hidden successfully! output saved to:", outname)



# decoding functions 



def extract_bits_from_pixels(data):
    pixel_start = get_pixel_data_offset(data)
    bits = []

    # read LSB of every byte after pixel_start
    for i in range(pixel_start, len(data)):
        bits.append(data[i] & 1)

    return bits


def bits_to_string(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        value = int("".join(str(b) for b in byte_bits), 2)
        chars.append(chr(value))
    return "".join(chars)


def decode_message_from_image(data):
    bits = extract_bits_from_pixels(data)
    raw_text = bits_to_string(bits)

    # Search for markers
    start_index = raw_text.find(start_marker)
    end_index = raw_text.find(end_marker)

    if start_index == -1 or end_index == -1:
        return None  # no valid message found

    return raw_text[start_index + len(start_marker) : end_index]

def reveal_mode():
    print("\n--- REVEAL (decode) MODE ---")

    # --- Loop until a valid BMP file is opened ---
    while True:
        filename = input("enter BMP filename to read hidden message from: ").strip()
        data = open_image_file(filename)

        if data is None:
            print("file not found. please check filename and try again.")
            continue

        if not is_bmp_file(data):
            print("error: file is not a BMP image. try again.")
            continue

        bpp = get_bits_per_pixel(data)
        if bpp not in (8, 24):
            print("error: unsupported bits-per-pixel value:", bpp)
            continue

        # valid file → stop looping
        break

    # --- ask for the seed (password) and regenerate markers ---
while True:
    secret_key = input("please enter the password used to hide the message (or type 'quit' to exit): ").strip() 
    # allow the user to exit the password loop
    if secret_key.upper() == "QUIT":
            return  # exit the entire reveal_mode function
    
    # regenerate the markers using the key and the unique suffixes
    start_marker = generate_marker(secret_key + "alpha")
    end_marker = generate_marker(secret_key + "omega")

    # passing regenerated markers
    message = decode_message_from_image(data, start_marker, end_marker)

    if message is None:
        print("no hidden message found in this image, or the key was incorrect. please try again. ")
    else:
        print("\nhidden message found:")
        print(message)
        break 

# main menu 


while True:
    print("\n--- STEGANOGRAPHY PROGRAM ---")
    print("enter 'hide' to hide a message")
    print("enter 'reveal' to reveal a message")

    choice = input("enter an option: ").strip().lower()
    choice= choice.upper()

    try:
        if choice=="HIDE":
            hide_mode()
        elif choice=="REVEAL":
            reveal_mode()

    except:
        print("invalid choice. please try again.")



