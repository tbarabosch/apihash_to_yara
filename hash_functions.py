#!/usr/bin/env python
# Jay Smith
# jay.smith@fireeye.com
# 
########################################################################
# Copyright 2012 Mandiant
# Copyright 2014 FireEye
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
########################################################################
# Traverse a directory, trying to find all exports for all valid PE
# executable files. Computes common shellcode hashes and stores them
# to a sqlite database file for later use, such as in IDA Pro.

# !!!!!!!!!!!!
# Edited by Thomas Barabosch (@tbarabosch) so that it can be used with api_hash_to_yara
# Refere to https://github.com/fireeye/flare-ida/blob/master/shellcode_hashes/make_sc_hash_db.py
# for the original code
# !!!!!!!!!!!!

import zlib
from crccheck.crc import Crc32Bzip2

############################################################
# Start of functions to implement operator primitives
############################################################

ROTATE_BITMASK = {
    8  : 0xff,
    16 : 0xffff,
    32 : 0xffffffff,
    64 : 0xffffffffffffffff,
}

def rcr(inVal, numShifts, cb, dataSize=32):
    '''rotate carry right instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    #make sure carry in bit is only 0 or 1
    cb = cb & 1
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    #or the carry value in there
    bitMask = ROTATE_BITMASK[dataSize]
    inVal = inVal | (cb << dataSize)
    x = (dataSize - numShifts) + 1
    res = (inVal >> numShifts) | (inVal << x)
    return (bitMask & res, 1 & (res >> dataSize))

def ror(inVal, numShifts, dataSize=32):
    '''rotate right instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    bitMask = ROTATE_BITMASK[dataSize]
    return bitMask & ((inVal >> numShifts) | (inVal << (dataSize-numShifts)))

def rol(inVal, numShifts, dataSize=32):
    '''rotate left instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    bitMask = ROTATE_BITMASK[dataSize]
    currVal = inVal
    return bitMask & ((inVal << numShifts) | (inVal >> (dataSize-numShifts)))

############################################################
# Start of hash implementations
############################################################

def poisonIvyHash(inStr,fName):
    #need a null at the end of the string
    if inStr[-1] != '\x00':
        inStr = inStr + '\x00'
    cx = 0xffff
    dx = 0xffff
    for b1 in inStr:
        bx = 0
        ax = ord(b1) ^ (cx & 0xff)
        cx =  ((cx>>8)&0xff) | ((dx&0xff)<<8)
        dx = ((dx>>8)&0xff) | 0x800
        while (dx & 0xff00) != 0:
            c_in = bx & 1
            bx = bx >> 1
            ax, c_out = rcr(ax, 1, c_in, 16)
            if c_out != 0:
                ax = ax ^ 0x8320
                bx = bx ^ 0xedb8
            dx =  (dx&0xff) | (((((dx>>8)&0xff)-1)&0xff)<<8)
        cx = cx ^ ax
        dx = dx ^ bx
    dx = 0xffff & ~dx
    cx = 0xffff & ~cx
    return  0xffffffff & ((dx<<16) | cx)

pseudocode_poisonIvyHash = '''Too hard to explain.\nString hash function from POISON IVY RAT.\nSee code for information'''


def rol3XorEax(inString,fName):
    if inString is None:
        return 0
    ecx = 0
    eax = 0
    for i in inString:
        eax = eax | ord(i)
        ecx = ecx ^ eax
        ecx = rol(ecx, 0x3, 32)
        ecx += 1
        eax = 0xffffffff & (eax << 8)
    return ecx

pseudocode_rol3XorEax = '''eax := 0;
ecx := 0;
for c in input_string {
    eax := eax | c ;
    ecx := ecx ^ eax;
    ecx := ROL(ecx, 0x3);
    ecx : ecx + 1;
    eax := 0xffffffff & (eax << 8);
};
return ecx;
'''

def rol7AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x7, 32)
        val += ord(i)
    return val

pseudocode_rol7AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 7):
   acc := acc + c;
}
'''

def rol5AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x5, 32)
        val += ord(i)
    return val

pseudocode_rol5AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 5):
   acc := acc + c;
}
'''

def addRor4WithNullHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString + "\x00":
        val = (val & 0xffffff00) + ((val + ord(i)) & 0xff)
        val = ror(val, 0x4, 32)
    return val

pseudocode_addRor4WithNullHash32 = '''acc := 0;
for c in input_string_with_trailing_NULL {
   acc := (acc & 0xffffff00) + ((acc + c) & 0xff);
   acc := ROR(acc, 4):
}
'''


def ror7AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0x7, 32)
        val += ord(i)
    return val

pseudocode_ror7AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 7):
   acc := acc + c;
}
'''

def ror9AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0x9, 32)
        val += ord(i)
    return val

pseudocode_ror9AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 9);
   acc := acc + c;
}
'''

def ror11AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0xb, 32)
        val += ord(i)
    return val

pseudocode_ror11AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 11);
   acc := acc + c;
}
'''

def ror13AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0xd, 32)
        val += ord(i)
    return val

pseudocode_ror13AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 13);
   acc := acc + c;
}
'''

def ror13AddWithNullHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString + "\x00":
        val = ror(val, 0xd, 32)
        val += ord(i)
    return val

pseudocode_ror13AddWithNullHash32 = '''acc := 0;
for c in input_string_with_trailing_NULL {
   acc := ROR(acc, 13);
   acc := acc + c;
}
'''

def ror13AddHash32Sub1(inString,fName):
    '''Same as ror13AddHash32, but subtract 1 afterwards'''
    return ror13AddHash32(inString,fName) - 1

pseudocode_ror13AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 13);
   acc := acc + c;
}
acc := acc - 1;
'''

def shl7Shr19XorHash32(inString,fName):
    val = 0
    for i in inString:
        edx = 0xffffffff & (val << 7)
        ecx = 0xffffffff & (val >> 0x19)
        eax = edx | ecx
        t = 0xff & (ord(i) ^ 0xf4)
        val = eax ^ t
    return val

pseudocode_shl7Shr19XorHash32 = '''acc := 0;
for c in input_string {
   t0 = (acc << 7);
   t1 = (acc >> 0x19);
   t2 = t0 | t1;
   acc = t2 ^ c ^ 0xf4;
}
'''

def sll1AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        b = ord(i)
        b = 0xff & (b | 0x60)
        val = val + b
        val = val << 1
        val = 0xffffffff & val
    return val

pseudocode_sll1AddHash32 = '''acc := 0;
for c in input_string {
    acc = acc + (c | 0x60);
    acc = acc << 1;
}
'''

def crc32(inString,fName):
    return 0xffffffff & (zlib.crc32(inString.encode()))

def ror13AddHash32AddDll(inString,fName):
    dllHash = 0
    for c in fName:
        dllHash = ror(dllHash, 0xd, 32)
        if ord(c) < 97:
            dllHash = int(dllHash) + ord(c)
        else:
            dllHash = int(dllHash) + ord(c) - 32
        dllHash = ror(dllHash, 0xd, 32)
    dllHash = ror(dllHash, 0xd, 32)
    dllHash = ror(dllHash, 0xd, 32)

    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0xd, 32)
        val += ord(i)
    val = ror(val, 0xd, 32)
    val += dllHash
    if val >= 4294967296:
        val -= 4294967296
    return val

pseudocode_ror13AddHash32AddDll = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 13);
   acc := acc + c;
}
acc := acc + ror13add(DllName);
'''

def mult21AddHash32(inString,fName):
    acc = 0
    for i in inString:
        acc = 0xffffffff & (acc * 0x21)
        acc = 0xffffffff & (acc + ord(i))
    return acc


pseudocode_hashMult21 = '''acc := 0;
for c in input_string {
   acc := acc * 0x21;
   acc := acc + c;
}
'''

def add1505Shl5Hash32(inString,fName):
  val = 0x1505
  for ch in inString:
    val += (val << 5)
    val &= 0xFFFFFFFF
    val += ord(ch)
    val &= 0xFFFFFFFF
  return val

pseudocode_add1505Shl5Hash32 = '''val := 0x1505;
for c in input_string {
   val := val +  (val << 5);
   val := val + c;
}
'''

def rol7XorHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x7, 32)
        val = val ^ (0xff & ord(i))
    return val

pseudocode_rol7XorHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 7):
   acc := acc ^ c;
}
'''

def rol7AddXor2Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x7, 32)
        val += (ord(i) ^ 2)
    return val

pseudocode_rol7AddXor2Hash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 7):
   acc := acc + (c ^ 2);
}
'''

def dualaccModFFF1Hash(inString,fName):
    if inString is None:
        return 0

    v4, v8 = 0, 1
    for ltr in inString:
        v8 = (ord(ltr) + v8) % 0x0FFF1
        v4 = (v4 + v8) % 0x0FFF1
    return (v4 << 0x10)|v8

pseudocode_dualaccModFFF1Hash = '''
acc_1 := 0
acc_2 := 0
for c in input_string {
    acc_2 = (acc_2 + c) % 0x0FFF1
    acc_1 = (acc_1 + acc2) % 0x0FFF1
}
return (acc_1 << 0x10) | acc2
'''

def hash_Carbanak(inString,fName):
    a2 = map(ord, inString)
    ctr = 0
    for i in a2:
        ctr = (ctr << 4) + i
        if (ctr & 0xF0000000):
            ctr = (((ctr & 0xF0000000) >> 24) ^ ctr) & 0x0FFFFFFF

    return ctr

pseudocode_hash_Carbanak = '''
    acc_1 = 0
    for c in input_string:
        acc_1 = (acc_1 << 4) + c
        if (acc_1 & 0xF0000000):
            acc_1 = (((acc_1 & 0xF0000000) >> 24) ^ acc_1) & 0x0FFFFFFF
    return acc_1
'''

def hash_ror13AddUpperDllnameHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    dllHash = 0
    for i in fName:
        dllHash = ror(dllHash, 0xd, 32)
        b = ord(i)
        if b >= 0x61:
            b -= 0x20
        dllHash += b
        dllHash = 0xffffffff & dllHash
    for i in inString:
        val = ror(val, 0xd, 32)
        val += ord(i)
        val = 0xffffffff & val
    return 0xffffffff & (dllHash + val)



pseudocode_hash_ror13AddUpperDllnameHash32 = '''
acc := 0
dllhash := 0
for i in dllname {
   dllhash := ROR(acc, 13);
   dllhash := dllhash + toupper(c);
}
for i in input_string {
   acc := ROR(acc, 13);
   acc := acc + toupper(c);
}
return  acc + dllhash
'''

# as seen in Neutrino Bot launcher
def fnv1Xor67f(inString,fName):
    val = 0x811c9dc5
    for c in inString:
        val = (0x1000193 * (ord(c) ^ val)) & 0xffffffff
    return val ^ 0x67f

pseudocode_fnv1Xor67f = '''
    acc = 0x811c9dc5
    for c in inString:
        acc = (0x1000193 * (ord(c) ^ acc)) & 0xffffffff
    return acc ^ 0x67f
    return acc
'''

def ror13AddHash32DllSimple(inString,fName):
    dll_hash = 0
    for c in fName:
        dll_hash = ror(dll_hash, 0xd, 32)
        if ord(c) < 97:
            dll_hash = int(dll_hash) + ord(c)
        else:
            dll_hash = int(dll_hash) + ord(c) - 32

    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0xd, 32)
        val += ord(i)
    val += dll_hash
    return val & 0xFFFFFFFF

pseudocode_ror13AddHash32DllSimple = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 13);
   acc := acc + c;
}
acc := acc + ror13add(dll_name);
'''

def imul83hAdd(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = val * 131
        val += ord(i)
    val = val & 0xFFFFFFFF
    return val

pseudocode_imul83hAdd = '''acc := 0;
for c in input_string {
   acc := acc * 83h:
   acc := acc + c;
}
'''

def ror13AddHash32Sub20h(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = ror(val, 0xd, 32)
        if ord(i) < 97:
            val = int(val) + ord(i)
        else:
            val = int(val) + ord(i) - 32
    return val

pseudocode_ror13AddHash32Sub20h = '''acc := 0;
for c in input_string {
   acc := ROR(acc, 13);
   if (c > 0x61)
       c = c - 0x20;
   acc := acc + c;
}
'''

def rol3XorHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x3, 32)
        val = val ^ ord(i)
    return val

pseudocode_rol3XorHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 3):
   acc := acc ^ c;
}
'''

def chAddRol8Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = val ^ (ord(i) * 256)
        val = rol(val, 0x8, 32)
        val_hex = "%08x"%val
        valh_str = val_hex[4:6]
        valh = int(valh_str, 16)
        val = val ^ valh
    return val

pseudocode_chAddRol8Hash32 = '''acc := 0;
for c in input_string {
   acc := ch ^ c
   acc := ROL(acc, 8):
   acc := cl ^ ch;
}
'''

def xorShr8Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0xFFFFFFFF
    for i in inString:
        ci = ord(i)
        ci = ci ^ val
        ci = ci * val
        ci_hex = "%16x"%ci
        ci_hex = ci_hex[8:16]
        ci_hex = int(ci_hex, 16)
        shr8 = val >> 8
        val = ci_hex ^ shr8
    return val

pseudocode_xorShr8Hash32 = '''acc := 0;
for c in input_string {
   acc = (acc >> 8) ^ acc * (acc ^ c);
}
'''

def addRor13Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val += ord(i)
        val = ror(val, 0xd, 32)
    return val

pseudocode_addRor13Hash32 = '''acc := 0;
for c in input_string {
   acc := acc + c;
   acc := ROR(acc, 13);
}
'''

def addRor13HashOncemore32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val += ord(i)
        val = ror(val, 0xd, 32)
    val = ror(val, 0xd, 32)
    return val

pseudocode_addRor13HashOncemore32 = '''acc := 0;
for c in input_string {
   acc := acc + c;
   acc := ROR(acc, 13);
}
acc := ROR(acc, 13);
'''

def addRol5HashOncemore32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val += ord(i)
        val = rol(val, 0x5, 32)
    val = rol(val, 0x5, 32)
    return val

pseudocode_addRol5HashOncemore32 = '''acc := 0;
for c in input_string {
   acc := acc + c;
   acc := ROL(acc, 5);
}
acc := ROL(acc, 5);
'''


def or21hXorRor11Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    ors = 0
    for i in inString:
        ors = ord(i) | 33
        val = val ^ ors
        val = rol(val, 0xb, 32)
    return val

pseudocode_or21hXorRor11Hash32 = '''acc := 0;
for c in input_string {
   chr_or := chr | 21h;
   acc := acc ^ chr_or;
   acc := ROR(acc, 11);
}
'''

def or23hXorRor17Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    ors = 0
    for i in inString:
        ors = ord(i) | 35
        val = val ^ ors
        val = rol(val, 0x11, 32)
    return val

pseudocode_or23hXorRor17Hash32 = '''acc := 0;
for c in input_string {
   chr_or := chr | 23h;
   acc := acc ^ chr_or;
   acc := ROR(acc, 17);
}
'''

def rol9AddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x9, 32)
        val += ord(i)
    return val

pseudocode_rol9AddHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 9):
   acc := acc + c;
}
'''

def rol9XorHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x9, 32)
        val = val ^ ord(i)
    return val

pseudocode_rol9XorHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 9):
   acc := acc ^ c;
}
'''

def xorRol9Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = val ^ ord(i)
        val = rol(val, 0x9, 32)
    return val

pseudocode_xorRol9Hash32 = '''acc := 0;
for c in input_string {
   acc := acc ^ c;
   acc := ROL(acc, 9):
}
'''

def shl7Shr19AddHash32(inString,fName):
    val = 0
    for i in inString:
        edx = 0xffffffff & (val << 7)
        ecx = 0xffffffff & (val >> 0x19)
        eax = edx | ecx
        t = 0xff & ord(i)
        val = eax + t
    return val

pseudocode_shl7Shr19AddHash32 = '''acc := 0;
for c in input_string {
   t0 = (acc << 7);
   t1 = (acc >> 0x19);
   t2 = t0 | t1;
   acc = t2 + c;
}
'''

def playWith0xe8677835Hash(inString,fName):
    val = 0xFFFFFFFF
    for i in inString:
        val ^= ord(i)
        for j in range(0, 8):
            if (val&0x1) == 1:
                val ^= 0xe8677835
            val >>= 1
    return val ^ 0xFFFFFFFF

pseudocode_playWith0xe8677835Hash = '''
TBC
'''

def rol5XorHash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = rol(val, 0x5, 32)
        ors = ord(i) | 32
        val = val ^ ors
    return val

pseudocode_rol5XorHash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 5):
   acc := acc ^ c;
}
'''

def shl7SubHash32DoublePulser(inString,fName):
    eax = 0
    edi = 0
    for i in inString:
        edi = 0xffffffff & (eax << 7)
        eax = 0xffffffff & (edi - eax)
        eax = eax + (0xff & ord(i))
    edi = 0xffffffff & (eax << 7)
    eax = 0xffffffff & (edi - eax)
    return eax

pseudocode_shl7SubHash32DoublePulser = '''acc := 0;
for c in input_string {
   t0 = (acc << 7);
   t2 = t0 - t1;
   acc = t2 + c;
}
'''

def imul21hAddHash32(inString,fName):
    if inString is None:
        return 0
    val = 0x1505
    for i in inString:
        val = (val * 0x21) & 0xFFFFFFFF
        val = (val + (ord(i) & 0xFFFFFFDF)) & 0xFFFFFFFF
    return val

pseudocode_imul21hAddHash32 = '''acc := 0x1505;
for c in input_string {
   acc := acc * 21h;
   acc := acc + (c & 0xFFFFFFDF);
}
acc := SHL(acc, 7) - acc
'''

def shr2Shl5XorHash32(inString,fName):
    result = 0x4e67c6a7
    if inString.startswith("Nt") or inString.startswith("Zw"):
        inString = inString[2:]
    for i in inString:
        result ^= (ord(i) + (result >> 2) + (result << 5)) & 0xffffffff
    return result

pseudocode_shr2Shl5XorHash32 = '''acc := 0x4e67c6a7;
if input_string.startswith("Nt") or input_string.startswith("Zw") {
   input_string += 2;
}
for c in input_string {
   t0 := (acc >> 2);
   t1 := (acc << 5);
   acc := acc ^ (c + t0 + t1);
}
'''

def rol8Xor0xB0D4D06Hash32(inString,fName):
    if inString is None:
        return 0
    val = 0
    for i in inString:
        val = val ^ (ord(i) & 0xDF)
        val = rol(val, 0x8, 32)
        val = val + (ord(i) & 0xDF)
    return (val ^ 0xB0D4D06) & 0xffffffff

pseudocode_rol8Xor0xB0D4D06Hash32 = '''acc := 0;
for c in input_string {
   acc := ROL(acc, 8):
   acc := acc ^ c ^ 0xB0D4D06;
}
Smork_bot
'''

def bzip2_crc32(inString, fName):
    return Crc32Bzip2.calc(bytearray(inString.lower().encode()))

pseudocode_bzip2_crc32 = ""

############################################################

# The list of tuples of (supported hash name, hash size, pseudo_code)
HASH_TYPES = [
    ('ror7AddHash32', ror7AddHash32,      32, pseudocode_ror7AddHash32),
    ('ror9AddHash32', ror9AddHash32,       32, pseudocode_ror9AddHash32),
    ('ror11AddHash32',  ror11AddHash32,     32, pseudocode_ror11AddHash32),
    ('ror13AddHash32', ror13AddHash32,     32, pseudocode_ror13AddHash32),
    ('ror13AddWithNullHash32', ror13AddWithNullHash32, 32, pseudocode_ror13AddWithNullHash32),
    ('ror13AddHash32AddDll', ror13AddHash32AddDll,   32, pseudocode_ror13AddHash32AddDll),
    ('ror13AddHash32DllSimple', ror13AddHash32DllSimple,  32, pseudocode_ror13AddHash32DllSimple),
    ('ror13AddHash32Sub20h', ror13AddHash32Sub20h, 32, pseudocode_ror13AddHash32Sub20h),
    ('ror13AddHash32Sub1', ror13AddHash32Sub1,  32, pseudocode_ror13AddHash32),
    ('addRor4WithNullHash32', addRor4WithNullHash32,   32, pseudocode_addRor4WithNullHash32),
    ('addRor13Hash32', addRor13Hash32,     32, pseudocode_addRor13Hash32),
    ('addRor13HashOncemore32',  addRor13HashOncemore32,    32, pseudocode_addRor13HashOncemore32),
    ('rol3XorEax', rol3XorEax,          32, pseudocode_rol3XorEax),
    ('rol3XorHash32', rol3XorHash32,       32, pseudocode_rol3XorHash32),
    ('rol5AddHash32',  rol5AddHash32,      32, pseudocode_rol5AddHash32),
    ('addRol5HashOncemore32',  addRol5HashOncemore32,     32, pseudocode_addRol5HashOncemore32),
    ('rol7AddHash32',   rol7AddHash32,    32, pseudocode_rol7AddHash32),
    ('rol7AddXor2Hash32',  rol7AddXor2Hash32,       32, pseudocode_rol7AddXor2Hash32),
    ('rol7XorHash32',  rol7XorHash32,      32, pseudocode_rol7XorHash32),
    ('rol5XorHash32',   rol5XorHash32,      32, pseudocode_rol5XorHash32),
    #('rol8Xor0xB0D4D06Hash32',  rol8Xor0xB0D4D06Hash32,      32, pseudocode_rol8Xor0xB0D4D06Hash32),
    ('chAddRol8Hash32',  chAddRol8Hash32,   32, pseudocode_chAddRol8Hash32),
    ('rol9AddHash32', rol9AddHash32,      32, pseudocode_rol9AddHash32),
    ('rol9XorHash32', rol9XorHash32,       32, pseudocode_rol9XorHash32),
    ('xorRol9Hash32',  xorRol9Hash32,       32, pseudocode_xorRol9Hash32),
    ('shl7Shr19XorHash32',  shl7Shr19XorHash32,   32, pseudocode_shl7Shr19XorHash32),
    ('shl7Shr19AddHash32',  shl7Shr19AddHash32,   32, pseudocode_shl7Shr19AddHash32),
    #('shl7SubHash32DoublePulser',   shl7SubHash32DoublePulser,   32, pseudocode_shl7SubHash32DoublePulser),
    ('sll1AddHash32',  sll1AddHash32,      32, pseudocode_sll1AddHash32),
    ('shr2Shl5XorHash32',  shr2Shl5XorHash32, 32, pseudocode_shr2Shl5XorHash32),
    ('xorShr8Hash32',  xorShr8Hash32,      32, pseudocode_xorShr8Hash32),
    ('imul83hAdd',    imul83hAdd,       32, pseudocode_imul83hAdd),
    ('imul21hAddHash32',  imul21hAddHash32,          32, pseudocode_imul21hAddHash32),
    ('or21hXorRor11Hash32',    or21hXorRor11Hash32,       32, pseudocode_or21hXorRor11Hash32),
    ('or23hXorRor17Hash32',  or23hXorRor17Hash32,         32, pseudocode_or23hXorRor17Hash32),
    #('playWith0xe8677835Hash', playWith0xe8677835Hash,  32, pseudocode_playWith0xe8677835Hash),
    ('poisonIvyHash',  poisonIvyHash,      32, pseudocode_poisonIvyHash),
    ('crc32',   crc32,            32, 'Standard crc32'),
    ('mult21AddHash32',   mult21AddHash32,       32, pseudocode_hashMult21),
    #('add1505Shl5Hash32',  add1505Shl5Hash32,      32, pseudocode_add1505Shl5Hash32),
    #('dualaccModFFF1Hash',  dualaccModFFF1Hash,      32, pseudocode_dualaccModFFF1Hash),
    ('hash_Carbanak',   hash_Carbanak,          32, pseudocode_hash_Carbanak),
    ('hash_ror13AddUpperDllnameHash32', hash_ror13AddUpperDllnameHash32, 32, pseudocode_hash_ror13AddUpperDllnameHash32),
    #('fnv1Xor67f', fnv1Xor67f, 32, pseudocode_fnv1Xor67f),
    ('bzip2_crc32', bzip2_crc32, 32, pseudocode_bzip2_crc32),
]
