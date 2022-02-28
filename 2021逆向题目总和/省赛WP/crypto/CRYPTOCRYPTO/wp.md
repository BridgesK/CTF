
和普通的MT19937预测差别不大，只是题目中一直通过`renc`函数对`state`进行异或改变，所以异或恢复回来即可

``````python
from random import *

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES


def invert_right(m, l, val=''):
    length = 32
    mx = 0xffffffff
    if val == '':
        val = mx
    i, res = 0, 0
    while i*l < length:
        mask = (mx << (length-l) & mx) >> i*l
        tmp = m & mask
        m = m ^ tmp >> l & val
        res += tmp
        i += 1
    return res


def invert_left(m, l, val):
    length = 32
    mx = 0xffffffff
    i, res = 0, 0
    while i*l < length:
        mask = (mx >> (length-l) & mx) << i*l
        tmp = m & mask
        m ^= tmp << l & val
        res |= tmp
        i += 1
    return res


def invert_temper(m):
    m = invert_right(m, 18)
    m = invert_left(m, 15, 4022730752)
    m = invert_left(m, 7, 2636928640)
    m = invert_right(m, 11)
    return m


def clone_mt(record):
    state = [invert_temper(i) for i in record]
    gen = Random()
    gen.setstate((3, tuple(state+[0]), None))
    return gen


def init(r):
    sl = []
    for _ in range(624):
        x = os.urandom(4)
        sl.append(bytes_to_long(x))
    st = (3, tuple(sl + [0]), None)
    r.setstate(st)


def gsu(r):
    return r.getstate()[1][-1] % 624


def ss(r, sl, u):
    s = (3, tuple(sl + [u]), None)
    r.setstate(s)


def gsl(r):
    return r.getstate()[1][:-1]


def renc(r, rkey):
    sl = gsl(r)
    su = gsu(r)
    nsl = []
    for i in sl:
        nsl.append(i ^ rkey)
    ss(r, nsl, su)


with open('output', 'r') as f:
    numbers = f.readline().strip().split(',')
ciphertext = numbers[-1]
prng = list(map(int, numbers[:624]))

record = prng

state = [invert_temper(i) for i in record]
for i in range(624):
    for j in range(0, i):
        state[i] ^= (j % 256)
        
gen = Random()
gen.setstate((3, tuple(state+[0]), None))
g = gen
tmp = []
for i in range(624):
    tmp.append(g.getrandbits(32))
    renc(g, i % 256)
key = long_to_bytes(g.getrandbits(128))

print(ciphertext)
h = AES.new(key, AES.MODE_ECB)
print(h.decrypt(long_to_bytes(int(ciphertext, 16))))
# b'0000000000flag{5FSB8f5ZRwouow77tT09V4icpflf0AIg}'

``````

