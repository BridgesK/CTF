#coding:utf-8
from Crypto.PublicKey import RSA
import ContinuedFractions, Arithmetic
from Crypto.Util.number import *
from struct import pack,unpack
import zlib
import gmpy
import hashlib

# ①
# def wiener_hack(e, n):
#     frac = ContinuedFractions.rational_to_contfrac(e, n)
#     convergents = ContinuedFractions.convergents_from_contfrac(frac)
#     for (k, d) in convergents:
#         if k != 0 and (e * d - 1) % k == 0:
#             phi = (e * d - 1) // k
#             s = n - phi + 1
#             discr = s * s - 4 * n
#             if (discr >= 0):
#                 t = Arithmetic.is_perfect_square(discr)
#                 if t != -1 and (s + t) % 2 == 0:
#                     print("Hacked!")
#                     return d
#     return False
#
# n = 151092363916177851152025151918241584641682210212036254637668925062407387596818893923128056380386244596150134405578253100187360613990057596729265767426618262474915825169178445560157476701330766996735046666440633251722785157310664928275249725806466188778983132016426476941426227570021630850606892034122220619913
# e = 8336175595129952911533542789423826996569722546516271636161500363234194699197831564741315089461869306051343021000467004786843886241187253481694116720349730349091091395871354352082596957433423648367398183367388782648648524548000549086553610297047964333156830786192545363469852460230159194760278103213655609189
# d = wiener_hack(e, n)
# c = 51084654001062999676284508744761337160593155669881973332922269056143420517629679695048487021241292007953887627491190341353167847566083172502480747704275374070492531393399916651443961186981687573379323436438906676133035045064486529453649419053918833072924346775468502743027859482041178726542991466613589539914
# m1 = long_to_bytes(pow(c, d, n))
# print m1


# ②
# def my_parse_number(number):
#     string = "%x" % number
#     #if len(string) != 64:
#     #    return ""
#     erg = []
#     while string != '':
#         erg = erg + [chr(int(string[:2], 16))]
#         string = string[2:]
#     return ''.join(erg)
# def extended_gcd(a, b):
#     x,y = 0, 1
#     lastx, lasty = 1, 0
#     while b:
#         a, (q, b) = b, divmod(a,b)
#         x, lastx = lastx-q*x, x
#         y, lasty = lasty-q*y, y
#     return (lastx, lasty, a)
# def chinese_remainder_theorem(items):
#   N = 1
#   for a, n in items:
#     N *= n
#   result = 0
#   for a, n in items:
#     m = N/n
#     r, s, d = extended_gcd(n, m)
#     if d != 1:
#       N=N/n
#       continue
#       #raise "Input not pairwise co-prime"
#     result += a*s*m
#   return result % N, N
# sessions=[{"c": 24168576475826731342981309869386844888048819155804916609868467364828794195081900378454942799582364951590154660883127133517306279315632213654294241046389472660162658285116025022019193389467425762033793233310853287285710051131156746537960416278314488047201950871542871471614834606092674080171837479678908485762, "e": 3, "n": 0x57696c78e1d443a3c9211963c721c16e47068eb3b52dfb79ef55af340e7894c7e301a5f38734ddd10e67d0dd2f5759ae0443ca47719d82bfcccc9d26b05043b0b66b253219f266ea133fc613e23dbe14d5f731c5ad4158286a1139e2927b8a485df0e662d77277f61f4ff334a24b51959e399e5e778b6934897b6b9f4b315207L},
# {"c": 59042322068112449729750363498227925481549151238455994334741763136215058751527859574931116063334209500284095818008451340013716449554106507373112252757273078880364298445003064190906862585372984554264625861222115429779924444369582923270264732188891567089849725691839301479707767233813043465943547876632578498984, "e": 3, "n": 0xc7e5c4318b4376a93588ea853a70f5576aaa3a291acff806f87b00b01443edfd9298915343e8d219fc09ab464c02d12fa72abb0e70d40b12c63274bcf4a61ccb7c81d42fbb04f54e9ce972c3467c851932ecf8f0ada57f56ee91dad3837669fc501d69c68dce305d62cd1f09acff28874792ef343fca185bdc9d2432fd45d3d1L},
# {"c": 86124343357786577132154304914637897169467679024253471444678880447274558440276584635040507167438356800005540641456548793163113750596432451742228432593182300337042281015596655874375158300461112977200671847176880860698060672936210257455599090524023845268651175379694950602443080246153556268191330489901634436, "e": 3, "n": 0x8d0899da21f7a50a5a869b0914fdfbc7d67aa85941021403889d24cb5b8029dd45a14e02f83dba7c21b3759fb152e045dcad6f11421e578a1b01d5e0b077810fc33e5f8d6d8e3623d278c908bbf7f4f7adb7224014e1f14272214e1a05cf4314dd950290fddbec9870be2c1d100bcdaf7056a1b909a400bb1f549efbede68bcfL}]
#
# data = []
# for session in sessions:
#     e=session['e']
#     n=session['n']
#     msg=session['c']
#     data = data + [(msg, n)]
# print "Please wait, performing CRT"
# x, n = chinese_remainder_theorem(data)
# e=session['e']
# realnum = gmpy.mpz(x).root(e)[0].digits()
# m2 = my_parse_number(int(realnum))
# print m2


# ③
# import string
#
# n = 12382768780688845948585828171746451695620690637388724603203719934675129634162669400211587652801497553140445052212955447547285342951827548927777971592012005336108991182804517438932388430909818349339928033362693776498198280566445301283769762658236093273135470594245556180103947875110497679850836950853434075025187940546602828416710260312146348085635062790163306288554171471977697811571151068804586709977754482736587083043633360827556846476139372134496068081264161278183780518986923815627524813237434789592133132430580528353375704616450593022343415392743694469637309237497448893478902243349283615118435345397909237495251L
# p = 182635381484380563458311202271781328898053732908212705893542973352083240894286209775590202544476913342359034598901737742898345569752615514577169505593025259879429231797401548503324L
# e = 65537
# c = 7479226689503128706443123521570581658668839203982072419275773066090139369387752424856982287500754805036668221578674582111373214400048065981143586768159093517856729586240876781314226713473457848588205839635234624256432258024026698381646902196832849461804350553542541128509121012667792037004716033974053614737451942287543723238730054875983726091182977666880984732837604625557483621161056089767140997756267432137190239967241490004246596723655769407636914860893150081043179313259622038983431488143887092338693868571374510729082940832360819295528352729394196810748661957966996263811903630229686768254608968394381708296458
# dic = string.digits + "abcdef"
#
# for a in dic:
#      for b in dic:
#          pp = hex(p) + a + b
#          #p需要用0补全到1024位
#          pp += '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
#          #要加的数字与补全p时0的个数有关
#          pp = int(pp, 16)
#          p_fake = pp+0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
#          pbits = 1024
#          kbits = pbits-604
#          pbar = p_fake & (2^pbits-2^kbits)
#          print("upper %d bits (of %d bits) is given" % (pbits-kbits, pbits))
#          PR.<x> = PolynomialRing(Zmod(n))
#          f = x + pbar
#          try:
#              x0 = f.small_roots(X=2^kbits, beta=0.4)[0]  # find root < 2^kbits with factor >= n^0.4
#              p = x0 + pbar
#              print(x0 + pbar)
#          except:
#              pass

# q = n / p
# phi = (p-1) * (q-1)
# d = inverse(e, phi)
# m3 = long_to_bytes(pow(c, d, n))
# print m3


# text = m1 + m2 + m3
# print hashlib.new('md5', text).hexdigest()
