UNAME := $(shell uname)
UNAME_M := $(shell uname -m)

CXX = clang++
CXX_FLAGS =  -Wall -Wno-null-conversion -std=c++11 -g -O3 -fno-omit-frame-pointer -fPIC
CXX_DEFINES = -lpthread -ldl

.PHONY: x86_64 arm arm64

all:
ifeq ($(UNAME),Darwin)
	$(MAKE) macos_x64
else
    ifeq ($(UNAME_M),x86_64)
		$(MAKE) linux_x64
    else ifneq (,$(findstring arm,$(UNAME_M)))
		$(MAKE) linux_arm
    else
		$(MAKE) linux_arm64
    endif
endif

macos_x64:
	$(CXX) $(CXX_FLAGS) $(CXX_DEFINES) barrier.cpp detours.cpp disasm.cpp plthook_elf.c trampolinex64.S -D_ADM64_ -D_UNIX64 -shared -o libcorehook64.dylib

linux_arm:
	as trampolinearm32.S -o trampolinearm32.o -mfpu=vfpv4
	as -o trampolinearm.o trampolinearm.S -mimplicit-it=thumb -mfpu=vfpv4
	$(CXX) $(CXX_FLAGS) $(CXX_DEFINES) barrier.cpp detours.cpp disasm.cpp plthook_elf.c trampolinearm.o trampolinearm32.o -D_ARM_ -D_ARM32_ -shared -o libcorehook32.so
linux_arm64:
	$(CXX) $(CXX_FLAGS) $(CXX_DEFINES) barrier.cpp detours.cpp disasm.cpp plthook_elf.c trampolinearm64.S -D_ARM64_ -D_UNIX64 -shared -o libcorehook64.so
linux_x64:
	$(CXX) $(CXX_FLAGS) $(CXX_DEFINES) barrier.cpp detours.cpp disasm.cpp plthook_elf.c trampolinex64.S -D_ADM64_ -D_UNIX64 -shared -o libcorehook64.so

clean:
ifeq ($(UNAME),Darwin)
	rm -f libcorehook64.dylib
else
    ifneq (,$(findstring arm,$(UNAME_M)))
			rm -f trampolinearm.o
			rm -f trampolinearm32.o
			rm -f libcorehook32.so			
    else 
			rm -f libcorehook64.so
    endif	
endif

