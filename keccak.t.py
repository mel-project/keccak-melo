# This project is a differential fuzz test of the Melodeon Keccak implementation with
# the Python reference implementation created by Gilles Van Assche, of the Keccak team:
# https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
#
# The Python implementation has not been altered, only the original Keccak functions have been
# added and along with the differential fuzz testing functionality.

from colorama import Fore, Style
import pexpect
import random
import re

def ROL64(a, n):
    return ((a >> (64-(n%64))) + (a << (n%64))) % (1 << 64)

def KeccakF1600onLanes(lanes):
    R = 1
    for round in range(24):
        # θ
        C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        D = [C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1) for x in range(5)]
        lanes = [[lanes[x][y]^D[x] for y in range(5)] for x in range(5)]
        # ρ and π
        (x, y) = (1, 0)
        current = lanes[x][y]
        for t in range(24):
            (x, y) = (y, (2*x+3*y)%5)
            (current, lanes[x][y]) = (lanes[x][y], ROL64(current, (t+1)*(t+2)//2))
        # χ
        for y in range(5):
            T = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = T[x] ^((~T[(x+1)%5]) & T[(x+2)%5])
        # ι
        for j in range(7):
            R = ((R << 1) ^ ((R >> 7)*0x71)) % 256
            if (R & 2):
                lanes[0][0] = lanes[0][0] ^ (1 << ((1<<j)-1))
    return lanes

def load64(b):
    return sum((b[i] << (8*i)) for i in range(8))

def store64(a):
    return list((a >> (8*i)) % 256 for i in range(8))

def KeccakF1600(state):
    lanes = [[load64(state[8*(x+5*y):8*(x+5*y)+8]) for y in range(5)] for x in range(5)]
    lanes = KeccakF1600onLanes(lanes)
    state = bytearray(200)
    for x in range(5):
        for y in range(5):
            state[8*(x+5*y):8*(x+5*y)+8] = store64(lanes[x][y])
    return state

def Keccak(rate, capacity, inputBytes, delimitedSuffix, outputByteLen):
    outputBytes = bytearray()
    state = bytearray([0 for i in range(200)])
    rateInBytes = rate//8
    blockSize = 0
    if (((rate + capacity) != 1600) or ((rate % 8) != 0)):
        return
    inputOffset = 0
    # === Absorb all the input blocks ===
    while(inputOffset < len(inputBytes)):
        blockSize = min(len(inputBytes)-inputOffset, rateInBytes)
        for i in range(blockSize):
            state[i] = state[i] ^ inputBytes[i+inputOffset]
        inputOffset = inputOffset + blockSize
        if (blockSize == rateInBytes):
            state = KeccakF1600(state)
            blockSize = 0
    # === Do the padding and switch to the squeezing phase ===
    state[blockSize] = state[blockSize] ^ delimitedSuffix
    if (((delimitedSuffix & 0x80) != 0) and (blockSize == (rateInBytes-1))):
        state = KeccakF1600(state)
    state[rateInBytes-1] = state[rateInBytes-1] ^ 0x80
    state = KeccakF1600(state)
    # === Squeeze out all the output blocks ===
    while(outputByteLen > 0):
        blockSize = min(outputByteLen, rateInBytes)
        outputBytes = outputBytes + state[0:blockSize]
        outputByteLen = outputByteLen - blockSize
        if (outputByteLen > 0):
            state = KeccakF1600(state)
    return outputBytes

def SHAKE128(inputBytes, outputByteLen):
    return Keccak(1344, 256, inputBytes, 0x1F, outputByteLen)

def SHAKE256(inputBytes, outputByteLen):
    return Keccak(1088, 512, inputBytes, 0x1F, outputByteLen)

def SHA3_224(inputBytes):
    return Keccak(1152, 448, inputBytes, 0x06, 224//8)

def SHA3_256(inputBytes):
    return Keccak(1088, 512, inputBytes, 0x06, 256//8)

def SHA3_384(inputBytes):
    return Keccak(832, 768, inputBytes, 0x06, 384//8)

def SHA3_512(inputBytes):
    return Keccak(576, 1024, inputBytes, 0x06, 512//8)

def KECCAK224(inputBytes):
    return Keccak(1152, 448, inputBytes, 0x01, 224//8)

def KECCAK256(inputBytes):
    return Keccak(1088, 512, inputBytes, 0x01, 256//8)

def KECCAK384(inputBytes):
    return Keccak(832, 768, inputBytes, 0x01, 384//8)

def KECCAK512(inputBytes):
    return Keccak(576, 1024, inputBytes, 0x01, 512//8)

FUNCS = [
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
    'keccak224',
    'keccak256',
    'keccak384',
    'keccak512'
]

def mapFuncs(index, bytes):
    match index:
        case 0:
            return SHA3_224(bytes)
        case 1:
            return SHA3_256(bytes)
        case 2:
            return SHA3_384(bytes)
        case 3:
            return SHA3_512(bytes)
        case 4:
            return KECCAK224(bytes)
        case 5:
            return KECCAK256(bytes)
        case 6:
            return KECCAK384(bytes)
        case 7:
            return KECCAK512(bytes)

def randBytes():
    numBytes = random.randint(0, 2048)
    return bytearray([random.randint(0, 255) for i in range(numBytes)])

def bytesToString(bytes):
    bytes = bytearray.fromhex(bytes)
    output = '['

    for byte in bytes:
        output += str(int(byte)) + ', '

    output += ']'
    return output


def DIFFERENTIAL_TEST(runs = 256):
    command = 'melorun keccak.melo -i'
    child = pexpect.spawn(command)
    child.expect('melorun>', timeout = 10)

    for i in range(runs):
        index = random.randint(0, 7)
        func = FUNCS[index]
        data = randBytes()

        command = func + '(' + bytesToString(data.hex()) + ')'
        child.sendline(command)
        child.expect('\\r\\n\\r\\n')
        output = child.before.decode('ascii')
        meloHash = re.search('x\"[a-z0-9]+\"', output).group()
        meloHash = meloHash[2:len(meloHash) - 1]

        pythonHash = mapFuncs(index, data).hex()

        if (meloHash == pythonHash):
            print('{:8} {:10}: {}'.format('Melodeon', func, meloHash))
            print('{:8} {:10}: {}\n'.format('Python', func, pythonHash))
        else:
            print(Fore.RED + 'Discrepency:\n')
            print('{:7} {:8}: {}'.format('Melodeon', func, meloHash))
            print('{:7} {:8}: {}\n'.format('Python', func, pythonHash))
            print('Input bytes: ', len(data), '\tData: ', data.hex())
            print(Style.RESET_ALL)
            break