# GPL 2 applies to entropybroker.
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.
VERSION=1.0

PREFIX=/usr/local/entropybroker
BIN=$(PREFIX)/bin
ETC=$(PREFIX)/etc
VAR=$(PREFIX)/var
PID=$(VAR)/run

CXX=g++
DEBUG= -g #-D_DEBUG #-fprofile-arcs -ftest-coverage # -pg -g
CXXFLAGS+=-O3 -DVERSION=\"${VERSION}\" $(DEBUG) -Wall -DCONFIG=\"${ETC}/entropybroker.conf\" -DCACHE=\"${VAR}/pools.dat\" -DPID_DIR=\"${PID}\"
LDFLAGS+=$(DEBUG) -lcrypto -lrt

OBJSeb=handle_client.o config.o error.o fips140.o handle_pool.o kernel_prng_rw.o log.o main.o math.o pool.o scc.o signals.o utils.o auth.o
OBJSsa=server_audio.o error.o utils.o kernel_prng_rw.o log.o protocol.o server_utils.o auth.o
OBJSst=server_timers.o log.o utils.o error.o kernel_prng_rw.o protocol.o server_utils.o auth.o
OBJSsv=server_v4l.o error.o log.o protocol.o kernel_prng_rw.o utils.o server_utils.o auth.o
OBJSss=server_stream.o error.o log.o protocol.o kernel_prng_rw.o utils.o server_utils.o auth.o
OBJSse=server_egd.o error.o log.o kernel_prng_rw.o protocol.o utils.o server_utils.o auth.o
OBJSclk=client_linux_kernel.o error.o kernel_prng_io.o kernel_prng_rw.o log.o math.o protocol.o utils.o auth.o
OBJScle=client_egd.o error.o log.o kernel_prng_rw.o math.o protocol.o utils.o auth.o
OBJSte=test_egd_speed.o utils.o kernel_prng_rw.o log.o error.o auth.o

all: entropy_broker eb_server_audio eb_server_timers eb_server_v4l eb_server_stream eb_client_linux_kernel eb_server_egd eb_client_egd eb_test_egd_speed

check:
	cppcheck -v --enable=all --std=c++11 --inconclusive . 2> err.txt

entropy_broker: $(OBJSeb)
	$(CXX) -Wall -W $(OBJSeb) $(LDFLAGS) -o entropy_broker

eb_server_audio: $(OBJSsa)
	$(CXX) -Wall -W $(OBJSsa) $(LDFLAGS) -lasound -o eb_server_audio

eb_server_timers: $(OBJSst)
	$(CXX) -Wall -W $(OBJSst) $(LDFLAGS) -o eb_server_timers

eb_server_v4l: $(OBJSsv)
	$(CXX) -Wall -W $(OBJSsv) $(LDFLAGS) -o eb_server_v4l

eb_server_stream: $(OBJSss)
	$(CXX) -Wall -W $(OBJSss) $(LDFLAGS) -o eb_server_stream

eb_server_egd: $(OBJSse)
	$(CXX) -Wall -W $(OBJSse) $(LDFLAGS) -o eb_server_egd

eb_client_egd: $(OBJScle)
	$(CXX) -Wall -W $(OBJScle) $(LDFLAGS) -o eb_client_egd

eb_client_linux_kernel: $(OBJSclk)
	$(CXX) -Wall -W $(OBJSclk) $(LDFLAGS) -o eb_client_linux_kernel

eb_test_egd_speed: $(OBJSte)
	$(CXX) -Wall -W $(OBJSte) $(LDFLAGS) -o eb_test_egd_speed

install: entropy_broker eb_server_audio eb_server_timers eb_server_v4l eb_server_stream eb_server_egd eb_client_linux_kernel eb_client_egd eb_test_egd_speed
	mkdir -p $(BIN) $(ETC) $(VAR) $(PID)
	cp entropy_broker $(BIN)
	cp eb_server_audio $(BIN)
	cp eb_server_timers $(BIN)
	cp eb_server_v4l $(BIN)
	cp eb_server_stream $(BIN)
	cp eb_server_egd $(BIN)
	cp eb_client_linux_kernel $(BIN)
	cp eb_client_egd $(BIN)
	cp eb_test_egd_speed $(BIN)
	cp eb_entropybroker.conf $(ETC)

clean:
	rm -f $(OBJSeb) $(OBJSsa) $(OBJSst) $(OBJSsv) $(OBJSss)$(OBJSse) $(OBJSclk) $(OBJSte) entropy_broker core *.da *.gcov *.bb* *.o eb_server_audio eb_server_timers eb_server_v4l eb_server_stream eb_server_egd eb_client_linux_kernel eb_client_egd eb_test_egd_speed

package: clean
	mkdir eb-$(VERSION)
	cp *.cpp *.h entropybroker.conf Makefile Changes readme.txt license.* eb-$(VERSION)
	cp -a doc eb-$(VERSION)
	tar czf eb-$(VERSION).tgz eb-$(VERSION)
	rm -rf eb-$(VERSION)