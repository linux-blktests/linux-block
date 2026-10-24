UFQ IOSCHED EXAMPLE SCHEDULERS
============================

# Introduction

This directory contains a simple example of the ufq IO scheduler. It is meant
to illustrate the different kinds of IO schedulers you can build with ufq;
new schedulers will be added as the project evolves across releases.

# Compiling the examples

There are a few toolchain dependencies for compiling the example schedulers.

## Toolchain dependencies

1. clang >= 16.0.0

The schedulers are BPF programs, and therefore must be compiled with clang. gcc
is actively working on adding a BPF backend compiler as well, but are still
missing some features such as BTF type tags which are necessary for using
kptrs.

2. pahole >= 1.25

You may need pahole in order to generate BTF from DWARF.

3. rust >= 1.85.0

Rust schedulers uses features present in the rust toolchain >= 1.85.0. You
should be able to use the stable build from rustup.

There are other requirements as well, such as make, but these are the main /
non-trivial ones.

## Compiling the kernel

In order to run a ufq scheduler, you'll have to run a kernel compiled
with the patches in this repository, and with a minimum set of necessary
Kconfig options:

```
CONFIG_BPF=y
CONFIG_IOSCHED_UFQ=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
```

It's also recommended that you also include the following Kconfig options:

```
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_PAHOLE_HAS_BTF_TAG=y
```

There is a `Kconfig` file in this directory whose contents you can append to
your local `.config` file, as long as there are no conflicts with any existing
options in the file.

## Getting a vmlinux.h file

You may notice that most of the example schedulers include a "vmlinux.h" file.
This is a large, auto-generated header file that contains all of the types
defined in some vmlinux binary that was compiled with
[BTF](https://docs.kernel.org/bpf/btf.html) (i.e. with the BTF-related Kconfig
options specified above).

The header file is created using `bpftool`, by passing it a vmlinux binary
compiled with BTF as follows:

```bash
$ bpftool btf dump file /path/to/vmlinux format c > vmlinux.h
```

`bpftool` analyzes all of the BTF encodings in the binary, and produces a
header file that can be included by BPF programs to access those types.  For
example, using vmlinux.h allows a scheduler to access fields defined directly
in vmlinux

The scheduler build system will generate this vmlinux.h file as part of the
scheduler build pipeline. It looks for a vmlinux file in the following
dependency order:

1. If the O= environment variable is defined, at `$O/vmlinux`
2. If the KBUILD_OUTPUT= environment variable is defined, at
   `$KBUILD_OUTPUT/vmlinux`
3. At `../../vmlinux` (i.e. at the root of the kernel tree where you're
   compiling the schedulers)
4. `/sys/kernel/btf/vmlinux`
5. `/boot/vmlinux-$(uname -r)`

In other words, if you have compiled a kernel in your local repo, its vmlinux
file will be used to generate vmlinux.h. Otherwise, it will be the vmlinux of
the kernel you're currently running on. This means that if you're running on a
kernel with ufq support, you may not need to compile a local kernel at
all.

### Aside on CO-RE

One of the cooler features of BPF is that it supports
[CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/) (Compile Once Run
Everywhere). This feature allows you to reference fields inside of structs with
types defined internal to the kernel, and not have to recompile if you load the
BPF program on a different kernel with the field at a different offset.

## Compiling the schedulers

Once you have your toolchain setup, and a vmlinux that can be used to generate
a full vmlinux.h file, you can compile the schedulers using `make`. The build
vendors libbpf and bpftool under `build/`, then compiles BPF objects with
`clang` and the userspace loader (for example `ufq_simple.c`) with `gcc`.

```bash
$ make -j($nproc)
```

## ufq_simple

A simple IO scheduler that provides an example of a minimal ufq scheduler.
Populates commonly used kernel-exposed BPF interfaces for testing the UFQ
scheduler framework in the kernel.

## pfq

Priority Fair Queue (PFQ) is an eBPF I/O scheduler built on the UFQ framework.
It provides weighted fair scheduling, request merging, and preferential
service for configured interactive threads.

UFQ handles block-layer integration and request lifecycle management, calling
PFQ's initialization, insertion, dispatch, and completion callbacks through
`struct_ops`. PFQ implements the scheduling policy; the userspace loader
loads the BPF program, configures it, and attaches the callbacks.

### Scheduling policy

Each disk has 96 logical queues, grouped by priority class, priority level,
and I/O type (read, write, or synchronous write). Requests with the same
classification share a queue. Scheduling has two levels:

- **Between queues:** a service tree orders queues by virtual time. When
  selecting a new queue, PFQ chooses the one with the lowest virtual time.
  Each dispatch increases that queue's virtual time in proportion to the
  request's sector count divided by the queue's weight. A higher weight
  therefore gives more service. A queue can dispatch a bounded batch of
  requests before participating in selection again.
- **Within a queue:** expired FIFO requests take precedence. Otherwise, PFQ
  selects candidates by sector position, preferring metadata and shorter seek
  distances. The sector index also supports adjacent-request merging.

Requests marked `BLK_MQ_INSERT_AT_HEAD` enter a separate list and are
dispatched before requests in the fair queues.

Configured interactive threads use the SPECIAL class, whose read requests
receive additional weight. An empty SPECIAL read queue may briefly retain
its service slot to wait for more requests. Later scheduler callbacks check
when this idle hold expires.

### Building and running

Use a kernel built with `CONFIG_IOSCHED_UFQ=y`. From this directory, run:

```bash
$ make pfq
$ sudo ./build/bin/pfq
```

Repeat `-i NAME` to configure interactive threads:

```bash
$ sudo ./build/bin/pfq -i firefox -i code
```

Names are matched exactly and case-sensitively against the current thread's
`comm`. Without `-i`, requests use normal I/O priority classification.

## bpftool feature detection (`llvm`, `libcap`, `libbfd`)

While building bpftool, you may see lines similar to:

```
Auto-detecting system features:
...                         clang-bpf-co-re: [ on  ]
...                                    llvm: [ OFF ]
...                                  libcap: [ OFF ]
...                                  libbfd: [ OFF ]
```

This matches a typical minimal build environment: CO-RE support is on, while
bpftool's optional links to LLVM (for some disassembly paths), libcap, and
libbfd are off. **`llvm: [ OFF ]` is not a build failure** for these examples;
the scheduler build can still complete (libbpf static library, bpftool,
`vmlinux.h` generation, BPF `.o` files, and final `ufq_simple` link with `gcc`).

If `libcap` or `libbfd` show `[ OFF ]`, you only miss optional bpftool features
that depend on those libraries; you do not need them for compiling and loading
the schedulers in this directory.
