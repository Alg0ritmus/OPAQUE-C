# ******************************************************************
# ----------------- TECHNICAL UNIVERSITY OF KOSICE -----------------
# ---Department of Electronics and Multimedia Telecommunications ---
# -------- FACULTY OF ELECTRICAL ENGINEERING AND INFORMATICS -------
# ------------ THIS CODE IS A PART OF A MASTER'S THESIS ------------
# ------------------------- Master thesis --------------------------
# -----------------Patrik Zelenak & Milos Drutarovsky --------------
# ---------------------------version 0.2.0 -------------------------
# --------------------------- 29-01-2024 ---------------------------
# ******************************************************************

# note that this is modulus L
L = 7237005577332262213973186563042994240857116359379907606001950938285454250989

def inverse_mod_l(a_in):
	# perform a_in^-1 mod L
	return pow(a_in,-1,L)

def XOR(a:int,constant: int):
	result = list(a.to_bytes(32, byteorder='big', signed=False))
	return int(bytearray([i^constant for i in result]).hex(),16)

#------------------------------

## TEST OF FUNCTION modl_l_inverse()
def generate_modl_l_inverse_test_vector(IN_hex:list[int], constant: int, rounds:int):
	IN = int(bytearray(iner).hex(),16)

	print("Calculating ...")
	for i in range(rounds):
		r = inverse_mod_l(IN)

		IN = XOR(r,constant)

	print("Result:")
	result = list(IN.to_bytes(32, byteorder='little', signed=False))
	print("{"+",".join([hex(i) for i in result])+"}")
	return result


##########################################################
##########################################################
##########################################################

## Feel free to change these variables

# iner[32] is input/output variable used in our test of
# function modl_l_inverse.
# NOTE: little endian order below
iner: list[int] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
]

# testing_constant is used in 'masking' part of modl_l_inverse test
testing_constant: int = 0x57
# rounds sets amount of for-loop cycles
rounds:int = 1000

modL_test_vec:list[int] = generate_modl_l_inverse_test_vector(iner,testing_constant,rounds)


################################################
# Rewrite variables in test_config.h
# NOTE: we are using delimiters that changes
# block of code in test_config.h.
# 
# If you move test_config.h elsewhere
# you need to set new file_path in code below.
# DELIMITERS: /* VECTORS MODULO L */, /* END VECTORS MODULO L */
#
# TODO: make it more generic

file_path = "test_config.h"
with open(file_path, 'r') as file:
    content = file.read()

start_delimiter = "/* VECTORS MODULO L */"
end_delimiter = "/* END VECTORS MODULO L */"

start_index = content.find(start_delimiter)
end_index = content.find(end_delimiter)
new_block = ''

if start_index != -1 and end_index != -1:
	new_block = f'''
	// Here r[32] is temporary variable used for intermediate
    // calculation in modl_l_inverse test.
    u8 r[32];

    // iner[32] is input/output variable used in our test of
    // function modl_l_inverse.
    u8 iner[32] = {"{"+",".join([hex(i) for i in iner])+"}"};

    // testing_constant is used in 'masking' part of modl_l_inverse
    // test, see in description above.
    const u8 testing_constant = {hex(testing_constant)};

    // modL_test_vec is test vector to which we compare result 
    // of modl_l_inverse test. Note that if you change variable 
    // 'rounds' or 'testing_constant' you need to change also
    // test vector. You can do it simply by generating test
    // vector using python sctipt 'py_modl_l_inverse.py'.
    // But please, change variables in python script so they
    // match with variables defined in this file section.
    const u8 modL_test_vec[32] = {"{"+",".join([hex(i) for i in modL_test_vec])+"}"};

    // rounds sets amount of for-loop cycles
    const int rounds = {rounds};
	'''

# write changes
content = content[:start_index] + start_delimiter + new_block + end_delimiter + content[end_index + len(end_delimiter):]

with open(file_path, 'w') as file:
	file.write(content)

