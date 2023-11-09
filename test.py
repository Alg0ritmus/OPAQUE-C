import secrets
import random

def I2OSP(longint, length=8):
    '''
    I2OSP(longint, length) -> bytes

    I2OSP converts a long integer into a string of bytes (an Octet String). 
    It is defined in the  PKCS #1 v2.1: RSA Cryptography Standard (June 14, 2002)
    '''
    from binascii import a2b_hex, b2a_hex
    hex_string = '%X' % longint
    if len( hex_string ) > 2 * length:
            return print( 'integer %i too large to encode in %i octets' % ( longint, length ) )
    return a2b_hex(  hex_string.zfill( 2 * length ) )



def I2OSP2(x, x_len):
    if x < 0 or x >= 256**x_len:
        raise ValueError("Integer too large for the specified length")
    return x.to_bytes(x_len, byteorder='big')



#arr = [1502514348, 2381400790, 1589432030, 285587561, 2154349796, 1443620098, 3378972613, 4160590097, 2200044613, 1764691186, 3637137350, 2002294599, 4124800331, 665880443, 889851675, 3049996475, 3085656286, 1220653718, 3438475557, 2562614526, 4036241375, 3819451420, 2674312900, 998504711, 1845885548, 2866561644, 630446247, 3525990865, 882154773, 3643481399, 3563662923, 3278668065, 2048673300, 2156312426, 1243021298, 553710401, 2657293509, 3739422051, 2486741060, 203339503, 2017841599, 928065142, 2678761907, 2742505196, 2205383338, 3289726211, 3396042652, 1881106393, 1095649096, 2885738315, 4265342897, 88099668, 722367366, 1964369021, 2240267361, 3076499604, 2600632899, 7256782, 2487694571, 1322534064, 96917877, 3987717661, 2663766706, 3794143527, 3525293238, 1007552192, 2261362288, 2756683776, 3617418236, 1242424336, 3227518379, 2752188715, 330074751, 3581270086, 4006250616, 2521753655, 3706150219, 2803248536, 3005225316, 4017975052, 3721236494, 3594668612, 589680989, 1991573957, 3617761718, 760576759, 89986017, 2212251512, 2705537949, 2167823003, 1069152174, 1018200535, 110804191, 3294455507, 1980187717, 792678666, 583020112, 3644820486, 2541073681, 4052429327]
#num =  [26, 1, 9, 7, 30, 13, 11, 27, 18, 25, 14, 11, 11, 12, 6, 5, 21, 30, 26, 7, 17, 30, 19, 2, 0, 3, 30, 19, 28, 23, 18, 31, 19, 28, 4, 24, 31, 13, 16, 30, 20, 0, 27, 21, 26, 6, 12, 20, 2, 14, 11, 14, 15, 28, 14, 9, 8, 27, 2, 11, 14, 23, 25, 21, 3, 17, 1, 27, 10, 32, 19, 29, 18, 32, 0, 25, 27, 24, 6, 19, 12, 23, 18, 3, 16, 12, 23, 20, 10, 18, 10, 9, 12, 17, 29, 11, 4, 17, 7, 12]
#
#print(arr)
#print('\n')
#print(num)
#print('\n')
#
#for i in range(len(arr)):
#    a = I2OSP(arr[i],num[i])
#    if a != None:
#        a = a.hex()
#        print("\nInteger:",arr[i])
#        print("Octet String (hex-",num[i],"): ")
#        print("["+",".join([f"0x{a[i:i+2]}" for i in range(len(a)) if i%2==0])+"]")

# Example usage:
integer_value = 32
byte_length = 2  # Change this to the desired byte length
octet_string = I2OSP(integer_value, byte_length)
octet_string2 = I2OSP2(integer_value, byte_length)
print([hex(a) for a in octet_string])
print([hex(a) for a in octet_string2])