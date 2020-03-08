FLAGS := -D__KERNEL__ -D__NR_CPUS__=$(shell nproc) -O2 -g
CLANG_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
CLANG_FLAGS += -Wall -Werror \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-gnu-variable-sized-type-not-at-end \
    -Wno-address-of-packed-member \
    -Wno-tautological-compare \
    -Wno-unknown-warning-option 

LLC_FLAGS := -march=bpf -mcpu=probe -mattr=dwarfris

CLANG ?= /home/litie/code/clang-9/bin/clang
LLC ?= /home/litie/code/clang-9/bin/llc

BPF = lxc_conntrac_01.o

lxc_conntrac_01.ll : lxc_conntrac_01.c
	${CLANG} ${MAX_LXC_OPTIONS} ${CLANG_FLAGS} -c $< -o $@

lxc_conntrac_01.o: lxc_conntrac_01.ll
	${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

all: $(BPF)

.PHONY: all
