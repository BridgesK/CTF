def unwater(infile , outfile):
    with open(infile , 'r') as f:
        raw = f.read()
        f.close()

    out = ''

    i = 0
    while(i < len(raw)):
        out += chr(ord(raw[i]) ^ (i % 0x10))
        i += 1

    o = open(outfile ,'w')
    o.write(out)
    o.close()

unwater('rsafrompcap' , 'rsapublickey.pem')
unwater('cxkfrompcap' , 'cxk.jpg')
unwater('secretfrompcap' , 'secret.wav')