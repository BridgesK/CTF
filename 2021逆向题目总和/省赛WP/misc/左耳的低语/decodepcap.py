n = 0xecb26f598a7997f96e51b4e1bf90cce834f15cf2470fc3d1159289e0feca9c74fbc685a923da0de50659d67ad7c1e099bf01d2be33212350c9a9e5ccce136162f512f7f8b1f5eb0e20cf7fa29bff436294a64442c3e69f64f705b85efb80ba057c9ed78f7eadba80fa318be9613402747582079b221d4274aaf46ab0e8d57125
d = 0x78ba0e475a74e88a05b5d10fafd8d85abbde3bed2b47a435f9cdd35b9a399791a775bb68e8eb6858df63651d24fd3364d7e2c32dd60059f5f3d61f6ad5d556beda6b5ef0537177e9fe0935a7cfb38804870fbf416914a4d127dfceb6a15f888bf9b8cf9e879a54c0900ce1d3d7634a010af15b9fdf32391441fb389d8dbf8085
e = 0x10001

def decode(text):
    tmp = hex(pow(int(text , 16) , d , n))[2:].strip('L')
    if(len(tmp) % 2):
        tmp = '0' + tmp
    return tmp.decode('hex')

def decode1(text):
    tmp = hex(pow(int(text , 16) , e , n))[2:].strip('L')
    if(len(tmp) % 2):
        tmp = '0' + tmp
    return tmp.decode('hex')


with open('137->1.txt' , 'r') as f:
    raw = f.read()
    f.close()

o = open('cxkfrompcap' , 'wb')
raw = raw.strip('\n').split('\n')
l = ''
for i in range(len(raw)):
    l += decode(raw[i])
o.write(l)
o.close()


with open('1->137.txt' , 'r') as f:
    raw = f.read()
    f.close()

o = open('secretfrompcap' , 'wb')
raw = raw.strip('\n').split('\n')
l = ''
for i in range(len(raw)):
    l += decode(raw[i])
o.write(l)
o.close()
