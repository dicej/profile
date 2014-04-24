.PHONY: all
all: build/profile

build/profile: build/profile.o
	gcc $(^) -lunwind -lunwind-x86_64 -lunwind-ptrace -lstdc++ -o $(@)

build/profile.o: src/profile.cpp
	@mkdir -p $(dir $(@))
	g++ -fno-rtti -fno-exceptions -Wall -Werror -g -O0 -c $(<) -o $(@)

.PHONY: clean
clean:
	rm -rf build
