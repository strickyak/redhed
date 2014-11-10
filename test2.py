from go import github.com/strickyak/redhed as rh

key = rh.NewKey('31415', 'xnmbcznxbcnzbcmnzxbcmbzcnmzbxnmc')

f1 = '0'
f2 = '_home_foo_gocode_src_github.com_strickyak_redhed'
f3 = 'XNMBCZNXBCNZBCMNZXBCMBZCNMZBXNMCZBCMXZBCMXZBCNXZBCMZBCNXZBCBCBBBNMBXZCNMBXZCNXZBCMBXZCMZXBCNMBXZNMCBXZNMBCXZN'

for f in [f1, f2, f3]:
  x = rh.EncryptFilename(f, key)
  y = rh.DecryptFilename(x, key)
  must y == f
  say len(f), len(x)
  say f
  say x

print "redhed/test2 OKAY."
