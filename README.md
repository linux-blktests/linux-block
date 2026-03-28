<!--
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (c) 2025 Western Digital Corporation or its affiliates.
-->

# blktests-kpd-ci
This is a collection of GitHub actions workflow scripts for Continuous
Integration (CI) of Linux kernel using blktests. The scripts are intended to be
triggered by [Kernel Patches Daemon](https://github.com/kernel-patches/kernel-patches-daemon).
To use the scripts, specify this repository and the main branch as "ci_repo" and
"ci_branch" parameters respectively in the Kernel Patches Daemon config file.
