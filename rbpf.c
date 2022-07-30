#include "bpf.h"
#include "config.h"
#include "debug.h"
#include "helper.h"

typedef struct {
    int array_fd;
    int ringbuf_fd;

    union {
        u8 bytes[PAGE_SIZE*8];
        u16 words[0];
        u32 dwords[0];
        u64 qwords[0];
        addr_t ptrs[0];
    };
} context_t;

int main(int argc, char** argv)
{
    int ret = 0;

    context_t *ctx = calloc(1, sizeof(context_t));

    if (!ctx) {
        WARNF("Failed to alloc context_t, running out of memory");
        goto abort;
    }

    ret = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(u32), PAGE_SIZE, 1);
    if (ret < 0) {
        WARNF("Failed to create array map: %d (%s)", ret, strerror(-ret));
        goto abort;
    }
    ctx->array_fd = ret;

    if ((ret = bpf_create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, PAGE_SIZE)) < 0) {
        WARNF("Could not create ringbuf map: %d (%s)", ret, strerror(-ret));
        goto abort;
    }
    ctx->ringbuf_fd = ret;

    struct bpf_insn insn[] = {
        BPF_MOV32_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN()
    };

    int prog = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insn, sizeof(insn) / sizeof(insn[0]), "");
    if (prog < 0) {
        WARNF("Could not load socket filter program:\n %s", bpf_log_buf);
        goto abort;
    }

    int err = bpf_prog_skb_run(prog, ctx->bytes, 8);

    if (err != 0) {
        WARNF("Could not run program(do_leak): %d (%s)", err, strerror(err));
        goto abort;
    }

    int key = 0;
    err = bpf_lookup_elem(ctx->array_fd, &key, ctx->bytes);
    if (err != 0) {
        WARNF("Could not lookup comm map: %d (%s)", err, strerror(err));
        goto abort;
    }

abort:
    if (prog > 0) close(prog);
    if (ctx) {
        if (ctx->array_fd >= 0) close(ctx->array_fd);
        if (ctx->ringbuf_fd >= 0) close(ctx->ringbuf_fd);
        free(ctx);
    }

    return ret;
}