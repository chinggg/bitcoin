#export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping "
#export LDFLAGS="-fprofile-instr-generate -fcoverage-mapping "
#LDFLAGS+='-fprofile-arcs' CFLAGS+='-fprofile-arcs -ftest-coverage' \
#CXXFLAGS+='-fprofile-arcs -ftest-coverage' CPPFLAGS+='-fprofile-arcs -ftest-coverage' \
fuzzopt="--enable-fuzz --with-sanitizers=fuzzer"
lcovopt="--enable-lcov --enable-lcov-branch-coverage"
CC=clang CXX=clang++ ./configure --enable-debug --with-gui=no $fuzzopt $lcovopt
