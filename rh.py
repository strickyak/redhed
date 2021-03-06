from go import crypto/sha256
from go import fmt
from go import io
from go import path
from go import os
from go import strings

from go import github.com/strickyak/redhed as rh

from ../aphid import flag

def Usage():
  fmt.Fprintf(os.Stderr, """
    Usage:
      rh e keyid password infilePlain outfileEncrypted # Encrypt
      rh d keyid password infileEncrypted outfilePlain # Decrypt
""")
  os.Exit(13)

def main(args):
  args = flag.Munch(args)
  if len(args) == 5:
    cmd, id, pw, src, dst = args
    key = rh.NewKey(id, sha256.Sum256(pw))

    if cmd == 'e': # encrypt
      r = os.Open(src)
      with defer r.Close():
        st = r.Stat()
        modt = st.ModTime().Unix()
        fd = os.Create(dst)
        with defer fd.Close():
          w = rh.NewWriter(fd, key, src, modt)
          io.Copy(w, r)
          w.Close()
      return
      
    elif cmd == 'd': # decrypt
      fd = os.Open(src)
      with defer fd.Close():
        r = rh.NewReader(fd, key)
        w = os.Create(dst)
        with defer w.Close():
          io.Copy(w, r)
          r.Close()
      return

  if len(args) == 4:
    cmd, id, key, p = args
    key = rh.NewKey(id, sha256.Sum256(pw))

    if cmd == 'E': # Encrypt filename.
      p = path.Clean(p)
      must p != '.', 'empty name not allowed'
      v = []
      for s in strings.Split(p, '/'):
        must s
        v.append(rh.EncryptFilename(s, key))
      fmt.Println(strings.Join(v, '/'))
      return

    if cmd == 'D': # Decrypt filename.
      p = path.Clean(p)
      must p != '.', 'empty name not allowed'
      v = []
      for s in strings.Split(p, '/'):
        must s
        v.append(rh.DecryptFilename(s, key))
      fmt.Println(strings.Join(v, '/'))
      return

  Usage()
