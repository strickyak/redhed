from go import io/ioutil
from go import os

from go import github.com/strickyak/redhed as rh

# Independantly define these.
sectorSize = 4096
gcmOverhead = 16
headLen = 16
middleLen = 20

path = 'alpha/beta/gamma'
must rh.PayloadLenFromPath(path) == sectorSize - headLen - middleLen - len(path) - gcmOverhead

must int(rh.ChunkLen) == sectorSize
must int(rh.GcmOverhead) == gcmOverhead
must int(rh.HeadLen) == headLen
must int(rh.MiddleLen) == middleLen

########################################

h = go_new(rh.Holder) {
  Time: 12345678901234,
  Size: 9876543219876, 
  Offset: 888777666555,
  Path: 'github.com/strickyak/redhed',
  Payload: byt([x+9 for x in range(rh.PayloadLenFromPath('github.com/strickyak/redhed'))])
  }
h2 = go_new(rh.Holder)
h2.FromBytes( h.Bytes() )
must h2.Time == 12345678901234
must h2.Size == 9876543219876
must h2.Offset == 888777666555
must h2.Path == 'github.com/strickyak/redhed'
must h2.Payload == byt([x+9 for x in range(rh.PayloadLenFromPath('github.com/strickyak/redhed'))])

########################################

must rh.Encode5bits(1) == ord('A')
must rh.Encode5bits(2) == ord('B')
must rh.Encode5bits(26) == ord('Z')
must rh.Encode5bits(32 + 1) == ord('A')
must rh.Encode5bits(32*5 + 2) == ord('B')
must rh.Encode5bits(32*32*2 + 26) == ord('Z')
must except rh.Encode5bits(0)
must except rh.Encode5bits(27)
must except rh.Encode5bits(31)

must rh.Decode5bits(ord('A')) == 1
must rh.Decode5bits(ord('B')) == 2
must rh.Decode5bits(ord('Z')) == 26
must rh.Decode5bits(ord('a')) == 1
must rh.Decode5bits(ord('b')) == 2
must rh.Decode5bits(ord('z')) == 26
must except rh.Decode5bits(ord('0'))
must except rh.Decode5bits(ord('5'))
must except rh.Decode5bits(ord('~'))
must except rh.Decode5bits(0)
must except rh.Decode5bits(13)

must rh.DecodeKeyID('99') == 99
must rh.DecodeKeyID('32767') == 32767

say rh.DecodeKeyID('AAA')
say rh.DecodeKeyID('AAB')
say rh.DecodeKeyID('ABA')
say rh.DecodeKeyID('BAA')
say rh.DecodeKeyID('aaz')
say rh.DecodeKeyID('aza')
say rh.DecodeKeyID('zaa')

must rh.DecodeKeyID('AAA') == -32768 + 1*32*32 + 1*32 + 1
must rh.DecodeKeyID('AAB') == -32768 + 1*32*32 + 1*32 + 2
must rh.DecodeKeyID('ABA') == -32768 + 1*32*32 + 2*32 + 1
must rh.DecodeKeyID('BAA') == -32768 + 2*32*32 + 1*32 + 1
must rh.DecodeKeyID('aaz') == -32768 + 1*32*32 + 1*32 + 26
must rh.DecodeKeyID('aza') == -32768 + 1*32*32 + 26*32 + 1
must rh.DecodeKeyID('zaa') == -32768 + 26*32*32 + 1*32 + 1

########################################

for data in ['', 'Hello Redhed\n', byt([x+42 for x in range(10000)])]:

  F = '__test1.tmp'
  key = rh.NewKey('TMP', byt([x for x in range(32)]))
  fd = os.Create(F)
  w = rh.NewWriter(fd, key, path, 1234567890)
  w.Write(data)
  w.Close()
  fd.Close()

  fd = os.Open(F)
  r = rh.NewReader(fd, key)
  z = ioutil.ReadAll(r)
  must len(z) == len(data)
  if len(z) > 99:
    must str(z)[:99] == str(data)[:99]
    must str(z)[-99:] == str(data)[-99:]
  else:
    must str(z) == str(data)
  r.Close()
  fd.Close()

#########################################

print "redhed/test1 OKAY."
