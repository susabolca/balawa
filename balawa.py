# -*- coding: utf-8 -*-

import binascii
import struct
import base64
import json
import os
from Crypto.Cipher import AES, DES

key_1 = '1899f9da9e4929a63068bd38515766b60415ea9a63beab1d4e5c0d5229fc9c284e767eefb632e6421125f7cfa7117682' 
key_2 = 'c46749ff33a77a99f73ec7701c963fa217589bd191d6bfde1a9545e9680fe87da600e219e47d4339ebd051a91cb0cbbf'
key_3 = b"0D3E52B8"
key_4 = '275d065fbe6c0eb6f86380ea458c0c4f9813fefb2dd80dc75711a80c20f522959bc087d7db71e941'

def Glod(key):
    import random, time, hashlib
    random.seed(time.time())
    v = random.random()
    h = hashlib.md5()
    h.update(str(v).encode('utf-8'))
    h = h.hexdigest()
    des = DES.new(key_3, DES.MODE_ECB)
    n = h[:6] + "%02x"%len(key) + key + h[6:]
    m = ((len(n)-8)//8 + 1) * 8
    s = des.encrypt(n[:m].encode('utf-8'))
    o = binascii.b2a_hex(s)
    print("encoded:", o)
    #Earth(o)
    return o

def Earth(s):
    des = DES.new(key_3, DES.MODE_ECB)
    p = des.decrypt(binascii.a2b_hex(s))
    n = int(p[6:8], 16)
    k = p[8:n+8]
    #print("decoded:", k)
    return k

core_key = Earth(key_1)
meta_key = Earth(key_2)
file_hdr = Earth(key_4)
#print(core_key, meta_key)

def Water(file_path):

    global core_key, meta_key
    unpad = lambda s: s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]

    fi = open(file_path, 'rb')
    header = fi.read(8)
    
    assert header == file_hdr

    fi.seek(2,1)
    key_length = fi.read(4)
    key_length = struct.unpack('<I', bytes(key_length))[0]
    key_data = fi.read(key_length)
    key_data_array = bytearray(key_data)
    for i in range(0, len(key_data_array)):
        key_data_array[i] ^= 0x64
    key_data = bytes(key_data_array)
    cryptor = AES.new(core_key, AES.MODE_ECB)
    key_data = unpad(cryptor.decrypt(key_data))[17:]
    key_length = len(key_data)
    key_data = bytearray(key_data)
    key_box = bytearray(range(256))
    c = 0
    last_byte = 0
    key_offset = 0
    for i in range(256):
        swap = key_box[i]
        c = (swap + last_byte + key_data[key_offset]) & 0xff
        key_offset += 1
        if key_offset >= key_length:
            key_offset = 0
        key_box[i] = key_box[c]
        key_box[c] = swap
        last_byte = c
    meta_length = fi.read(4)
    meta_length = struct.unpack('<I', bytes(meta_length))[0]
    meta_data = fi.read(meta_length)
    meta_data_array = bytearray(meta_data)
    for i in range(0, len(meta_data_array)):
        meta_data_array[i] ^= 0x63
    meta_data = bytes(meta_data_array)
    meta_data = base64.b64decode(meta_data[22:])
    cryptor = AES.new(meta_key, AES.MODE_ECB)
    #print(unpad(cryptor.decrypt(meta_data)).decode('utf-8'))
    meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
    meta_data = json.loads(meta_data)
    print (meta_data)
    crc32 = fi.read(4)
    crc32 = struct.unpack('<I', bytes(crc32))[0]
    fi.seek(5, 1)
    image_size = fi.read(4)
    image_size = struct.unpack('<I', bytes(image_size))[0]
    image_data = fi.read(image_size)
    #with open('a.jpg', 'wb') as f:
    #    f.write(image_data)
    #raise Exception
    fmt = meta_data['format']
    file_name = fi.name.split("/")[-1].split(".ncm")[0] + '.' + meta_data['format']
    if os.path.exists(file_name):
        print("'%s' already exists, skipped." % file_name)
        return file_name 

    # use a temp file for write
    temp_file = "_ncmdump.tmp"
    #new_file = os.path.join(os.path.split(file_path)[0], file_name)
    ft = open(temp_file, 'wb')
    chunk = bytearray()
    while True:
        chunk = bytearray(fi.read(0x8000))
        chunk_length = len(chunk)
        if not chunk:
            break
        for i in range(1, chunk_length+1):
            j = i & 0xff
            chunk[i-1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
        ft.write(chunk)
    ft.close()
    fi.close()
    print("written to '%s'." % file_name)

    # fix picture
    if fmt == "mp3":
        from mutagen.mp3 import MP3
        from mutagen.id3 import ID3, APIC
        af = MP3(temp_file, ID3=ID3)
        af.pprint()
        af.tags.add(APIC(3, 'image/jpeg', 3, 'Front cover', image_data))
        af.save()

    elif fmt == "flac":
        from mutagen.flac import FLAC, Picture
        af = FLAC(temp_file)
        pic = Picture()
        pic.type = 3
        pic.mime = 'image/jpeg'
        pic.desc = "Front Cover"
        pic.data = image_data
        af.add_picture(pic)
        af.pprint()
        af.save()

    else:
        raise Exception

    # rename the file to dest
    if os.path.exists(file_name):
        os.remove(file_name)
    os.rename(temp_file, file_name)

    # return the new filename
    return file_name

def Fire():
    import os
    for fpath in os.listdir('.'):
        ext = os.path.splitext(fpath)[-1]
        if ext == ".ncm":
            print("Decoding '%s' ..." % fpath)
            Water(fpath)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='金木水火土')
    parser.add_argument('-k', "--key", type=str)
    args = parser.parse_args()

    if args.key:
        print(Glod(args.key))
    else:
        Fire()