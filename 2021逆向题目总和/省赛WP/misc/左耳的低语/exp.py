import re
with open('secret.wav') as f:
    raw = f.read()
    f.close()
head = raw[:0x2c]
datas = raw[0x2c:]
data = re.findall('.{4}' , datas)
left_data = []
right_data = []
for i in range(len(data)):
    left_data.append(data[i][:2])
    right_data.append(data[i][2:])

lsb = ''

for i in range(len(left_data)):
    lsb += bin(int(left_data[i].encode('hex') ,16))[2:].rjust(16 , '0')[7]

string = ''
aa = re.findall('.{8}' , lsb)
for i in range(len(aa)):
    string += chr(int(aa[i] , 2))

print string[:42]