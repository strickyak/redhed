all : clean rh/rh test

rh/rh : rh.py
	python ../rye/rye.py build rh.py

test:
	python ../rye/rye.py run test1.py
	python ../rye/rye.py run test2.py
	set -x ; expr foo/bar/baz = $$(rh/rh D foo xyzzy $$(rh/rh E foo xyzzy foo/bar/baz))
	echo OKAY redhed/Makefile

clean:
	-set -x ; for x in */ryemodule.go ; do test -f "$$x" && rm -rf `dirname $$x`/ ; done
	-rm -f __test1.tmp
