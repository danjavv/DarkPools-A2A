import random
import numpy as np
from bitarray import bitarray
from bitarray.util import *

class AES:

    def ShiftRow(self, input: bitarray(128)) -> bitarray(128): # type: ignore

        output = bitarray(128)

        output[0:8] = input[0:8]
        output[8:16] = input[40:48]
        output[16:24] = input[80:88]
        output[24:32] = input[120:128]

        output[32:40] = input[32:40]
        output[40:48] = input[72:80]
        output[48:56] = input[112:120]
        output[56:64] = input[24:32]

        output[64:72] = input[64:72]
        output[72:80] = input[104:112]
        output[80:88] = input[16:24]
        output[88:96] = input[56:64]

        output[96:104] = input[96:104]
        output[104:112] = input[8:16]
        output[112:120] = input[48:56]
        output[120:128] = input[88:96]

        return output

    def times(self, input: bitarray(8)) -> bitarray(8): # type: ignore
        output = input << 1
        a = [bitarray("00000000"), bitarray("00011011")]
        output = output ^ a[ba2int(input >> 7)]
        return output

    def MixColumn(self, input: bitarray(128)) -> bitarray(128): # type: ignore
        output = bitarray(128)

        output[0:8] = self.times(input[0:8]) ^ self.times(input[8:16]) ^ (input[8:16]) ^ (input[16:24]) ^ (input[24:32])
        output[8:16] = (input[0:8]) ^ self.times(input[8:16]) ^ self.times(input[16:24]) ^ (input[16:24]) ^ (input[24:32])
        output[16:24] = (input[0:8]) ^ input[8:16] ^ self.times(input[16:24]) ^ self.times(input[24:32]) ^ (input[24:32])
        output[24:32] = self.times(input[0:8]) ^ (input[0:8]) ^ input[8:16] ^ (input[16:24]) ^ self.times(input[24:32])

        output[32:40] = self.times(input[32:40]) ^ self.times(input[40:48]) ^ (input[40:48]) ^ (input[48:56]) ^ (input[56:64])
        output[40:48] = (input[32:40]) ^ self.times(input[40:48]) ^ self.times(input[48:56]) ^ (input[48:56]) ^ (input[56:64])
        output[48:56] = (input[32:40]) ^ input[40:48] ^ self.times(input[48:56]) ^ self.times(input[56:64]) ^ (input[56:64])
        output[56:64] = self.times(input[32:40]) ^ (input[32:40]) ^ input[40:48] ^ (input[48:56]) ^ self.times(input[56:64])

        output[64:72] = self.times(input[64:72]) ^ self.times(input[72:80]) ^ (input[72:80]) ^ (input[80:88]) ^ (input[88:96])
        output[72:80] = (input[64:72]) ^ self.times(input[72:80]) ^ self.times(input[80:88]) ^ (input[80:88]) ^ (input[88:96])
        output[80:88] = (input[64:72]) ^ input[72:80] ^ self.times(input[80:88]) ^ self.times(input[88:96]) ^ (input[88:96])
        output[88:96] = self.times(input[64:72]) ^ (input[64:72]) ^ input[72:80] ^ (input[80:88]) ^ self.times(input[88:96])

        output[96:104] = self.times(input[96:104]) ^ self.times(input[104:112]) ^ (input[104:112]) ^ (input[112:120]) ^ (input[120:128])
        output[104:112] = (input[96:104]) ^ self.times(input[104:112]) ^ self.times(input[112:120]) ^ (input[112:120]) ^ (input[120:128])
        output[112:120] = (input[96:104]) ^ input[104:112] ^ self.times(input[112:120]) ^ self.times(input[120:128]) ^ (input[120:128])
        output[120:128] = self.times(input[96:104]) ^ (input[96:104]) ^ input[104:112] ^ (input[112:120]) ^ self.times(input[120:128])

        return output

    def SBox(self, input: bitarray(8)) -> bitarray(8): # type: ignore

        t = bitarray(28)
        m = bitarray(64)
        l = bitarray(30)
        s = bitarray(8)

        output = bitarray(8)

        # Top linear layer
        t[1] = input[0] ^ input[3] 
        t[2] = input[0] ^ input[5]
        t[3] = input[0] ^ input[6]
        t[4] = input[3] ^ input[5]
        t[5] = input[4] ^ input[6]
        t[6] = t[1] ^ t[5]
        t[7] = input[1] ^ input[2]
        t[8] = input[7] ^ t[6]
        t[9] = input[7] ^ t[7]
        t[10] = t[6] ^ t[7]
        t[11] = input[1] ^ input[5]
        t[12] = input[2] ^ input[5]
        t[13] = t[3] ^ t[4]
        t[14] = t[6] ^ t[11]
        t[15] = t[5] ^ t[11]
        t[16] = t[5] ^ t[12]
        t[17] = t[9] ^ t[16]
        t[18] = input[3] ^ input[7]
        t[19] = t[7] ^ t[18]
        t[20] = t[1] ^ t[19]
        t[21] = input[6] ^ input[7]
        t[22] = t[7] ^ t[21]
        t[23] = t[2] ^ t[22]
        t[24] = t[2] ^ t[10]
        t[25] = t[20]^ t[17]
        t[26] = t[3] ^ t[16]
        t[27] = t[1] ^ t[12]

        # Middle non-linear
        m[1] = t[13] & t[6]
        m[2] = t[23] & t[8]
        m[4] = t[19] & input[7]
        m[6] = t[3] & t[16]
        m[7] = t[22] & t[9]
        m[9] = t[20] & t[17]
        m[11] = t[1] & t[15]
        m[12] = t[4] & t[27]
        m[14] = t[2] & t[10]
        m[3] = t[14] ^ m[1]
        m[5] = m[4] ^ m[1]
        m[8] = t[26] ^ m[6]
        m[10] = m[9] ^ m[6]
        m[13] = m[12] ^ m[11]
        m[15] = m[14] ^ m[11]
        m[16] = m[3] ^ m[2]
        m[17] = m[5] ^ t[24]
        m[18] = m[8] ^ m[7]
        m[19] = m[10] ^ m[15]
        m[20] = m[16] ^ m[13]
        m[21] = m[17] ^ m[15]
        m[22] = m[18] ^ m[13]
        m[23] = m[19] ^ t[25]
        m[24] = m[22] ^ m[23]
        m[27] = m[20] ^ m[21]

        # depth 1 till here
        m[25] = m[22] & m[20] 
        m[31] = m[20] & m[23]
        m[34] = m[21] & m[22]
        m[26] = m[21] ^ m[25]
        m[28] = m[23] ^ m[25]
        m[33] = m[27] ^ m[25]
        m[36] = m[24] ^ m[25]

        # depth 3 start
        m[29] = m[28] & m[27] 
        m[30] = m[26] & m[24]
        m[32] = m[27] & m[31]
        m[35] = m[24] & m[34]
        m[37] = m[21] ^ m[29]
        m[38] = m[32] ^ m[33]
        m[39] = m[23] ^ m[30] 
        m[40] = m[35] ^ m[36] 
        m[41] = m[38] ^ m[40]
        m[42] = m[37] ^ m[39]
        m[43] = m[37] ^ m[38]
        m[44] = m[39] ^ m[40] 
        m[45] = m[42] ^ m[41]

        m[46] = m[44] & t[6] 
        m[47] = m[40] & t[8]
        m[48] = m[39] & input[7]
        m[49] = m[43] & t[16]
        m[50] = m[38] & t[9]
        m[51] = m[37] & t[17]
        m[52] = m[42] & t[15]
        m[53] = m[45] & t[27]
        m[54] = m[41] & t[10]
        m[55] = m[44] & t[13]
        m[56] = m[40] & t[23]
        m[57] = m[39] & t[19]
        m[58] = m[43] & t[3]
        m[59] = m[38] & t[22]
        m[60] = m[37] & t[20]
        m[61] = m[42] & t[1]
        m[62] = m[45] & t[4]
        m[63] = m[41] & t[2]

        # Bottom linear
        l[0] = m[61] ^ m[62]
        l[1] = m[50] ^ m[56]
        l[2] = m[46] ^ m[48]
        l[3] = m[47] ^ m[55]
        l[4] = m[54] ^ m[58]
        l[5] = m[49] ^ m[61]
        l[6] = m[62] ^ l[5]
        l[7] = m[46] ^ l[3]
        l[8] = m[51] ^ m[59]
        l[9] = m[52] ^ m[53]
        l[10] = m[53] ^ l[4]
        l[11] = m[60] ^ l[2]
        l[12] = m[48] ^ m[51]
        l[13] = m[50] ^ l[0]
        l[14] = m[52] ^ m[61]
        l[15] = m[55] ^ l[1]
        l[16] = m[56] ^ l[0]
        l[17] = m[57] ^ l[1]
        l[18] = m[58] ^ l[8]
        l[19] = m[63] ^ l[4]
        l[20] = l[0] ^ l[1]
        l[21] = l[1] ^ l[7]
        l[22] = l[3] ^ l[12]
        l[23] = l[18] ^ l[2]
        l[24] = l[15] ^ l[9]
        l[25] = l[6] ^ l[10]
        l[26] = l[7] ^ l[9]
        l[27] = l[8] ^ l[10]
        l[28] = l[11] ^ l[14]
        l[29] = l[11] ^ l[17]
        s[0] = l[6] ^ l[24]
        s[1] = l[16] ^ l[26]
        s[2] = l[19] ^ l[28]
        s[3] = l[6] ^ l[21]
        s[4] = l[20] ^ l[22]
        s[5] = l[25] ^ l[29]
        s[6] = l[13] ^ l[27]
        s[7] = l[6] ^ l[23]
        s[1] = s[1] ^ 1
        s[2] = s[2] ^ 1
        s[6] = s[6] ^ 1
        s[7] = s[7] ^ 1

        for i in range(8):
          output[i] = s[i]

        return output

    def R(self, round):
        a = []
        temp = bitarray("00000001")
        a.append(temp)

        for i in range(9):
            a.append(self.times(a[i]))

        return a[round]

    def g(self, input: bitarray(32), round) -> bitarray(32): # type: ignore
        v0 = input[0:8]
        v1 = input[8:16]
        v2 = input[16:24]
        v3 = input[24:32]   

        input[0:8] = v1
        input[8:16] = v2
        input[16:24] = v3
        input[24:32] = v0

        for i in range(4):
            input[8*i:8*i + 8] = self.SBox(input[8*i:8*i + 8]) # Byte Substitution

        v0 = input[0:8]
        # round = bin(round)[2:].zfill(8)

        v0 = v0 ^ self.R(round - 1)

        input[0:8] = v0

        return input

    def KeyGen(self, key: bitarray(128), round) -> bitarray(128): # type: ignore
        w0 = key[0:32]
        w1 = key[32:64]
        w2 = key[64:96]
        w = key[96:128]
        w3 = key[96:128]

        w0 = w0 ^ self.g(w, round)
        w1 = w0 ^ w1
        w2 = w1 ^ w2
        w3 = w2 ^ w3

        key[0:32] = w0
        key[32:64] = w1
        key[64:96] = w2 
        key[96:128] = w3

        return key

    def circuit(self, key: bitarray(128), message: bitarray(128)): # type: ignore

        state = message ^ key # Key Addition

        for i in range(9):

            for j in range(16):
                state[8*j:8*(j+1)] = self.SBox(state[8*j:8*(j+1)]) # Byte Substitution

            state = self.ShiftRow(state) # Shift Row
            state = self.MixColumn(state) # Mix Columns

            key = self.KeyGen(key, i + 1) # Key Generation

            state = state ^ key # Key Addition

        for i in range(16):
            state[8*i:8*i + 8] = self.SBox(state[8*i:8*i + 8]) # Byte Substitution

        state = self.ShiftRow(state) # Shift Row
        key = self.KeyGen(key, 10) # Final round key generation
        state = state ^ key # Key Addition
        return state

if __name__=='__main__':
    message = bitarray(bin(random.getrandbits(128))[2:].zfill(128))
    message = bitarray("0"*128)
    print("Message: ", ba2hex(message))

    key = bitarray(bin(random.getrandbits(128))[2:].zfill(128))
    key = bitarray("0"*128)
    print("Key: ", ba2hex(key))

    aes = AES()
    ciphertext = aes.circuit(key, message)
    print("Ciphertext: ", ba2hex(ciphertext))

    # aes = AES()
    # # for i in range(1, 11):
    # print(ba2hex(aes.MixColumn(hex2ba("632FAFA2EB93C7209F92ABCBA0C0302B"))))