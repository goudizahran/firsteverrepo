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


def read_message_from_file():
    while True:
        filename = input("enter text file name to read message from (or enter 'quit' to cancel): ").strip()
        
        if filename.upper() == 'QUIT':
            return None 
        try:
            with open(filename, "r", encoding="utf-8") as f:
                message = f.read().strip() 
                return message
        
        
        except FileNotFoundError:
            print("error. text file not found. please check filename and try again.")
            
        except Exception as e:
            print(f"unexpected error: {e}")
            print("please ensure the file is valid and accessible, then try again.")
    


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
    pixel_start = get_pixel_data_offset(data)
    bpp = get_bits_per_pixel(data)
    bytes_per_pixel = bpp // 8

    usable_channels = bytes_per_pixel
    if bytes_per_pixel == 4:
        usable_channels = 3  # skip alpha

    total_usable_bytes = (len(data) - pixel_start)
    usable_bytes = (total_usable_bytes // bytes_per_pixel) * usable_channels

    required_bits = len(message) * 8
    return required_bits <= usable_bytes



def encode_message_into_pixels(data, message):
    # find where pixel data starts (we do not touch the BMP header)
    pixel_start = get_pixel_data_offset(data)

    # determine how many bytes each pixel uses (1 = 8-bit, 3 = 24-bit, 4 = 32-bit)
    bpp = get_bits_per_pixel(data)
    bytes_per_pixel = bpp // 8

    # convert every character in the message into 8 bits
    msg_bits = []
    for ch in message:
        bits = format(ord(ch), "08b")  # convert character to binary (8 bits)
        msg_bits.extend(int(b) for b in bits)

    # idx = position in the image byte array where we start writing
    idx = pixel_start
    bit_index = 0               # track which message bit we are writing
    total_bits = len(msg_bits)  # total number of bits to write

    # loop through and hide every bit of the message
    while bit_index < total_bits:

        # identify which byte (within each pixel) we are on:
        # for 24-bit: channel 0=R, 1=G, 2=B
        # for 32-bit: channel 0=R, 1=G, 2=B, 3=A
        channel = (idx - pixel_start) % bytes_per_pixel

        # skip the alpha channel in 32-bit BMP (we do not modify transparency to avoid corrupting the image)
        if bytes_per_pixel == 4 and channel == 3:
            idx += 1
            continue

        # write message bit into the least significant bit (LSB) of this pixel byte
        data[idx] = (data[idx] & 0xFE) | msg_bits[bit_index]

        # move to next message bit and next image byte
        bit_index += 1
        idx += 1

    return data  


def hide_mode():
    print("\n--- HIDE (encode) MODE ---")

    # loop until a valid BMP file is opened 
    while True:
        filename = input("enter BMP filename to hide message in (e.g., old.bmp): ").strip()
        data = open_image_file(filename)

        if data is None:
            print("file not found. please check filename and try again.")
            continue

        if not is_bmp_file(data):
            print("error: file is not a BMP image. try a different file.")
            continue

        bpp = get_bits_per_pixel(data)
        if bpp not in (8, 24, 32):
            print("error: unsupported bits-per-pixel value:", bpp)
            continue

        # success means we can break the loop
        break

    pixel_start = get_pixel_data_offset(data)
    
    # calculate maximum message capacity in characters 
    bpp = get_bits_per_pixel(data)
    bytes_per_pixel = bpp // 8
    usable_channels = bytes_per_pixel

    if bytes_per_pixel == 4:
        usable_channels = 3  # skip alpha channel

    total_usable_bytes = (len(data) - pixel_start)
    usable_bytes = (total_usable_bytes // bytes_per_pixel) * usable_channels

    max_message_bits = usable_bytes
    max_message_chars = max_message_bits // 8  # total available space including start & end markers

    # subtract marker size (6 chars for start marker, 6 chars for end marker, 12 chars in total)
    user_max_chars = max_message_chars - 12

    if user_max_chars < 0:
        user_max_chars = 0   # in case the imgae cannot even fit 12 chars, user_max_chars would be negative

    # get the seed (password) and generate markers 
    secret_key = input("please enter a password for the message: ").strip()
    # generate unique start and end markers based on the key
    start_marker = generate_marker(secret_key + "alpha")
    end_marker = generate_marker(secret_key + "omega")

    # loop for message input with ASCII-only validation 
    user_message = None
    while user_message is None:
        source_choice = input(
            "please enter 'D' to directly input your message, or 'F' to input a text file containing your message (or enter 'quit' to cancel): "
        ).strip().upper()

        current_message = None

        if source_choice == "D":
            current_message = input(f"please enter your secret message (max {user_max_chars} characters): ")

        elif source_choice == "F":
            current_message = read_message_from_file()
            if current_message is None:
                continue  # user chose to quit or file error

        elif source_choice == "QUIT":
            return

        else:
            print("invalid choice. please try again.")
            continue

        if current_message and current_message.strip():
            final_message_content = current_message.strip()

            # ASCII-only check for both input methods
            try:
                final_message_content.encode("ascii")
            except UnicodeEncodeError:
                print("error: message contains non-ASCII characters. please try again.")
                continue

            full_message = start_marker + final_message_content + end_marker

            if can_image_fit_message(data, full_message):
                user_message = final_message_content
                break
            else:
                print("error. message is too long for this image.")
                print("please try again with a shorter message. ")
                # user_message remains None, loop continues for new selection
        else:
            print("no message received. please try again.")

    # encode now that everything is valid
    final_message_to_hide = start_marker + user_message + end_marker
    new_data = encode_message_into_pixels(data, final_message_to_hide)

    # save new file
    output_filename = input("enter output BMP filename (e.g., new.bmp): ").strip()


    save_image_file(output_filename, new_data)
    print("message hidden successfully in:", output_filename)



# decoding functions 



def extract_bits_from_pixels(data):
    # find where pixel data begins (we skip the BMP header)
    pixel_start = get_pixel_data_offset(data)

    # determine how many bytes each pixel uses: 1 = 8-bit, 3 = 24-bit, 4 = 32-bit
    bpp = get_bits_per_pixel(data)
    bytes_per_pixel = bpp // 8

    bits = []       # list to store extracted LSB bits
    idx = pixel_start

    # read every pixel byte until end of file
    while idx < len(data):

        # identify which channel we are reading:
        # for 32-bit BMP: channel 3 = alpha, which we skip
        channel = (idx - pixel_start) % bytes_per_pixel

        # skip the alpha channel in 32-bit images (avoid transparency changes)
        if bytes_per_pixel == 4 and channel == 3:
            idx += 1
            continue

        # extract the least significant bit (LSB) from this pixel byte
        bits.append(data[idx] & 1)

        # move to the next byte in the image data
        idx += 1

    # return the full list of extracted bits
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


def decode_message_from_image(data, start_marker, end_marker):
    bits = extract_bits_from_pixels(data)
    raw_text = bits_to_string(bits)

    # search for markers
    start_index = raw_text.find(start_marker)
    end_index = raw_text.find(end_marker)

    if start_index == -1 or end_index == -1:
        return None  # no valid message found

    return raw_text[start_index + len(start_marker) : end_index]

def reveal_mode():
    print("\n--- REVEAL (decode) MODE ---")

    #  loop until a valid BMP file is opened 
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
        if bpp not in (8, 24, 32):
            print("error: unsupported bits-per-pixel value:", bpp)
            continue

        # valid file → stop looping
        break

    # ask for the seed (password) and regenerate markers 
    while True:
        secret_key = input("please enter the password used to hide the message (or enter 'quit' to exit): ").strip() 
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

    choice = input("enter an option: ").strip().upper()

    if choice == "HIDE":
        hide_mode()
    elif choice == "REVEAL":
        reveal_mode()
    else:
        print("invalid choice. please try again.")

