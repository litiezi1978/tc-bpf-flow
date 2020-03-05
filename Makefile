FLAGS := -D__NR_CPUS__=$(shell nproc) -O2 -g

CLANG_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
CLANG_FLAGS += -Wall -Werror -Wno-address-of-packed-member -Wno-unknown-warning-option
LLC_FLAGS := -march=bpf -mcpu=probe -mattr=dwarfris

CLANG ?= /home/litie/code/clang-9/bin/clang
LLC ?= /home/litie/code/clang-9/bin/llc

BPF = classifier3.o

classifier3.ll : classifier3.c
	${CLANG} ${MAX_LXC_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

classifier3.o: classifier3.ll
	${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

all: $(BPF)

.PHONY: all