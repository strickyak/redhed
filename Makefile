all : clean rh/rh test

rh/rh : rh.ry
	python ../rye/rye.py build rh.ry

test:
	python ../rye/rye.py run test1.ry
	python ../rye/rye.py run test2.ry
	set -x ; expr foo/bar/baz = $$(rh/rh D xyzzy $$(rh/rh E xyzzy foo/bar/baz))
	echo OKAY redhed/Makefile

clean:
	-set -x ; for x in */ryemodule.go ; do test -f "$$x" && rm -rf `dirname $$x`/ ; done
	-rm -f __test1.tmp
