import numpy

initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

ip_inv = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

exp_perm = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
 
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
 
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
 
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
 
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
 
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
 
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
 
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

permu = [16,  7, 20, 21,
         29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
         32, 27,  3,  9,
         19, 13, 30,  6,
         22, 11,  4, 25]

pc1 =  [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

shift_table = [1, 1, 2, 2,
               2, 2, 2, 2,
               1, 2, 2, 2,
               2, 2, 2, 1]

pc2 = [14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32]

def hex2bin(s):
    mp = {k: f"{int(k, 16):04b}" for k in "0123456789abcdef"}
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin


def bin2hex(s):
    mp = {f"{i:04b}": f"{i:x}" for i in range(16)}
    hex = ""
    for i in range(0, len(s), 4):
        ch = s[i:i+4]
        hex += mp[ch]
    return hex


def bin2dec(binary):
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal

def dec2bin(num):
    res = bin(num).replace("0b", "")
    if(len(res) % 4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

def permute(inp, table, n):
    out=""
    for i in range (n):
        out+=inp[table[i]-1]
    return out

def xor(a, b):
    out = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            out += "0"
        else:
            out += "1"
    return out


def left_shift(k, shifts):
    return k[shifts:] + k[:shifts]



def get_roundkeys(key):
    key=hex2bin(key)
    key=permute(key,pc1,56)
    # print("Key after PC-1: ",bin2hex(key))
    rk=[]
    L=key[0:28]
    R=key[28:56]
    for i in range(16):
        L=left_shift(L, shift_table[i])
        R=left_shift(R, shift_table[i])
        # print("Key at round",i+1,"after left circular shift:", bin2hex(L+R))
        rk.append(permute(L+R,pc2,48))
        # print("Key at round",i+1,"after PC-2:", bin2hex(L+R))
    return rk



def DES(message,roundkey):
    m=hex2bin(message)
    m=permute(m,initial_perm,64)
    # print("Plaintext after IP:", bin2hex(m))

    L=m[0:32]
    R=m[32:64]

    for i in range(16):
        R_exp=permute(R,exp_perm,48)
        R_xor=xor(R_exp,roundkey[i])
        R_sbox=""
        for j in range(8):
            curr=R_xor[j*6:j*6+6]
            row=bin2dec(int(curr[0]+curr[5]))
            col=bin2dec(int(curr[1]+curr[2]+curr[3]+curr[4]))
            R_sbox+= dec2bin(sbox[j][row][col])
        
        R_perm = permute(R_sbox,permu,32)

        round_res=xor(L,R_perm)
        L=R
        R=round_res
        # print("R at round", i+1, "after expansion:",bin2hex(R_exp))
        # print("R at round", i+1, "after first xor:",bin2hex(R_xor))
        # print("R at round", i+1, "after S-box:",bin2hex(R_sbox))
        # print("R at round", i+1, "after permutation:",bin2hex(R_perm))
        # print("R at round", i+1, "after second xor:",bin2hex(round_res))
        # print("Round",i+1,"result: ",bin2hex(L)," ",bin2hex(R),"   ",bin2hex(roundkey[i]))


    result = permute(R+L,ip_inv,64)
    return bin2hex(result)

    

def des_encrypt(plaintext, key):
    bin_text=""
    for i in range(len(plaintext)):
        bin_text+=dec2bin(ord(plaintext[i]))
    hex_text=bin2hex(bin_text)
    text_list=[hex_text[i:i+16] for i in range(0, len(hex_text), 16)]
    if len(text_list[len(text_list)-1])<16:
        L=len(text_list[len(text_list)-1])
        text_list[len(text_list)-1] += (16-L)*'0'

    rk=get_roundkeys(key)

    for i in range(len(text_list)):
        text_list[i]=DES(text_list[i],rk)
    
    return text_list

def des_decrypt(ciphertext, key):
    rk=get_roundkeys(key)[::-1]

    for i in range(len(ciphertext)):
        ciphertext[i]=DES(ciphertext[i],rk)
    
    for i in range(6):
        if ciphertext[len(ciphertext)-1][15-(2*i)] == 0 and ciphertext[len(ciphertext)-1][14-(2*i)] == 0:
            ciphertext[len(ciphertext)-1]=ciphertext[len(ciphertext)-1][:-2]
        else:
            break
    
    text1=""
    for i in range(len(ciphertext)):
        text1+=ciphertext[i]
    
    text1=hex2bin(text1)

    plaintext = ""
    for i in range(0, len(text1), 8):
        decimal_number = int(text1[i:i+8], 2)
        plaintext += chr(decimal_number)

    return plaintext

# print(des_decrypt(['83236c9906e3c8e7', 'd7ecd70629c3500f', '027d24d1770e2b1f', 'bee673c58e177e41'],"1234567890abcdef")) 

