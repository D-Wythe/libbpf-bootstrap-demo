// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET         2       /* Internet IP Protocol         */
#define AF_INET6        10
#define IPPROTO_SMC   	263

SEC("fmod_ret/update_socket_protocol")
int BPF_PROG(smc_run, int family, int type, int protocol)
{

        if ((family == AF_INET || family == AF_INET6) &&
            type == SOCK_STREAM &&
            (!protocol || protocol == IPPROTO_TCP)) {
                return IPPROTO_SMC;
        }

        return protocol;
}
