package redhed_test

import "github.com/strickyak/redhed"

import (
	"bufio"
	"io/ioutil"
	"os"
	"testing"
)

const N = 32 * 1024

var pw = "1234567890abcdefghij1234567890ab"

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func must(x bool) {
	if !x {
		panic("failed")
	}
}

func fn(w *redhed.StreamWriter) string {
	return "benchmark.file"
}

func run(magic int16, b *testing.B) {
	b.StopTimer()
	td, err := ioutil.TempDir("/tmp", "redhed_test")
	check(err)
	key := redhed.NewKey("12345", []byte(pw))

	w := redhed.NewStreamWriter(td, key, magic, 0, fn)
	bw := bufio.NewWriter(w)
	buf := make([]byte, N)
	b.StartTimer()
	for i := 0; i < 1000; i++ {
		n, err := bw.Write(buf)
		check(err)
		must(n == N)
		b.SetBytes(N)
	}
	w.Close()
	b.StopTimer()
	err = os.RemoveAll(td)
	check(err)
}

func BenchmarkOne(b *testing.B) {
	run(redhed.Magic1, b)
}
func BenchmarkTwo(b *testing.B) {
	run(redhed.Magic2, b)
}
