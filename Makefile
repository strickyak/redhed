all : clean rh/rh test

rh/rh : rh.py
	python ../rye/rye.py build rh.py

test:
	python ../rye/rye.py run test1.py
	python ../rye/rye.py run test2.py
	set -x ; expr foo/bar/baz = $$(rh/rh D foo xyzzy $$(rh/rh E foo xyzzy foo/bar/baz))
	echo OKAY redhed/Makefile

clean:
	-rm -f __test1.tmp
	T=`find . -name ryemain.go` ; set -x ; for x in $$T ; do rm -f $$x ; rmdir `dirname $$x` ; done
	T=`find . -name ryemodule.go` ; set -x ; for x in $$T ; do rm -f $$x ; D=`dirname $$x` ; B=`basename $$D` ; rm -f $$D/$$B ; rmdir $$D ; done
