/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF builds can reach glibc headers through Clang's host include paths.
 * On x86, the BPF target leaves __x86_64__ undefined, causing gnu/stubs.h
 * to include stubs-32.h, which may be absent without 32-bit glibc headers.
 * Put this empty substitute before the system headers in BPF include paths.
 */
