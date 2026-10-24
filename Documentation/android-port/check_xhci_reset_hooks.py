#!/usr/bin/env python3
"""Exercise extracted reset functions with register/timing/callback shims."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from check_scx_donor_retry import function

ROOT = Path(__file__).resolve().parents[2]
LTS = '2ff600d29ee478d0a8d46ef8a58afb5e038fe692'
ACK = '23112ce1886ea26b19be03207c0227a06a6ca009'
PATH = 'drivers/usb/host/xhci.c'
PRE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define XHCI_STATE_DYING 1
#define STS_HALT 1
#define CMD_RESET 2
#define STS_CNR 4
#define XHCI_INTEL_HOST 1
#define XHCI_ASMEDIA_MODIFY_FLOWCONTROL 2
enum soft_reset_phase { PRE_SOFT_RESET, SOFT_RESET_INITIATED, POST_SOFT_RESET };
struct usb_hcd { struct { void *controller; } self; };
struct regs { u32 status, command; };
struct bus { unsigned port_c_suspend, suspended_ports, resuming_ports; };
struct hub { struct bus bus_state; };
struct xhci_hcd {
    struct regs *op_regs;
    unsigned xhc_state, quirks;
    struct usb_hcd hcd;
    struct hub usb2_rhub, usb3_rhub;
};
static struct xhci_hcd *owner;
static int first_error, second_error, writes, delay_us, handshakes;
static int unsafe_callback_mmio, callback_active, phases;
static char phase_log[4], events[32];
static unsigned events_len;
static void event(char e) { assert(events_len + 1 < sizeof(events)); events[events_len++] = e; }
static u32 readl(u32 *reg) {
    if (callback_active) {
        if ((owner->quirks & XHCI_INTEL_HOST) && writes && delay_us < 1000)
            unsafe_callback_mmio++;
    } else event(reg == &owner->op_regs->status ? 's' : 'c');
    return *reg;
}
static void writel(u32 val, u32 *reg) { event('w'); writes++; *reg = val; }
static void udelay(unsigned us) { event('d'); delay_us += us; }
static struct usb_hcd *xhci_to_hcd(struct xhci_hcd *x) { return &x->hcd; }
static void *to_pci_dev(void *p) { return p; }
static void usb_asmedia_modifyflowcontrol(void *p) { assert(p == owner); event('a'); }
static int xhci_handshake(u32 *reg, u32 mask, u32 expected, u64 timeout) {
    assert(timeout == 1234 && expected == 0);
    if (handshakes++ == 0) {
        assert(reg == &owner->op_regs->command && mask == CMD_RESET);
        event('h'); return first_error;
    }
    assert(reg == &owner->op_regs->status && mask == STS_CNR);
    event('H'); return second_error;
}
#define xhci_warn(...) ((void)0)
#define xhci_dbg_trace(...) ((void)0)
static void trace_android_vh_dwc3_xhci_soft_reset(struct usb_hcd *hcd, enum soft_reset_phase phase) {
    assert(hcd == &owner->hcd && phase == phases && phases < 3);
    phase_log[phases++] = "PIO"[phase];
    callback_active = 1;
    (void)readl(&owner->op_regs->command);
    callback_active = 0;
}
'''
MAIN = r'''
struct scenario { const char *name; u32 status; unsigned state, quirks; int first, second; };
int main(void) {
    const struct scenario cases[] = {
        {"inaccessible", ~0U, 0, 0, 0, 0},
        {"dying-inaccessible", ~0U, XHCI_STATE_DYING, XHCI_INTEL_HOST, 0, 0},
        {"running", 0, 0, 0, 0, 0},
        {"success", STS_HALT, 0, 0, 0, 0},
        {"intel", STS_HALT, 0, XHCI_INTEL_HOST, 0, 0},
        {"reset-timeout", STS_HALT, 0, 0, -ETIMEDOUT, 0},
        {"reset-disappeared", STS_HALT, 0, XHCI_INTEL_HOST, -ENODEV, 0},
        {"not-ready-timeout", STS_HALT, 0, 0, 0, -ETIMEDOUT},
        {"asmedia", STS_HALT, 0, XHCI_ASMEDIA_MODIFY_FLOWCONTROL, 0, 0},
        {"intel-not-ready-timeout", STS_HALT, 0, XHCI_INTEL_HOST, 0, -ETIMEDOUT},
    };
    int total_unsafe = 0;
    puts("{\"observations\":[");
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const struct scenario *s = &cases[i];
        struct regs regs = { s->status, 0x100 };
        struct xhci_hcd x = { .op_regs = &regs, .xhc_state = s->state, .quirks = s->quirks };
        x.hcd.self.controller = &x;
        x.usb2_rhub.bus_state = (struct bus){1,2,3};
        x.usb3_rhub.bus_state = (struct bus){4,5,6};
        owner = &x;
        first_error = s->first; second_error = s->second;
        writes = delay_us = handshakes = unsafe_callback_mmio = callback_active = phases = 0;
        events_len = 0; memset(events, 0, sizeof(events)); memset(phase_log, 0, sizeof(phase_log));
        int ret = xhci_reset(&x, 1234);
        bool starts = s->status != ~0U && (s->status & STS_HALT);
        int expected = s->status == ~0U ? -ENODEV : !starts ? 0 : s->first ? s->first : s->second;
        assert(ret == expected);
        assert(writes == (starts ? 1 : 0));
        assert(handshakes == (!starts ? 0 : s->first ? 1 : 2));
        assert(phases == ((HAS_HOOKS && starts) ? 3 : 0));
        bool cleared = starts && !s->first;
        assert(x.usb2_rhub.bus_state.port_c_suspend == (cleared ? 0U : 1U));
        assert(x.usb2_rhub.bus_state.suspended_ports == (cleared ? 0U : 2U));
        assert(x.usb2_rhub.bus_state.resuming_ports == (cleared ? 0U : 3U));
        assert(x.usb3_rhub.bus_state.port_c_suspend == (cleared ? 0U : 4U));
        assert(x.usb3_rhub.bus_state.suspended_ports == (cleared ? 0U : 5U));
        assert(x.usb3_rhub.bus_state.resuming_ports == (cleared ? 0U : 6U));
        total_unsafe += unsafe_callback_mmio;
        printf("%s{\"case\":\"%s\",\"return\":%d,\"events\":\"%s\",\"phases\":\"%s\",\"unsafe_callback_mmio\":%d,\"command\":%u,\"bus_cleared\":%s}",
               i ? ",\n" : "", s->name, ret, events, phase_log, unsafe_callback_mmio, regs.command, cleared ? "true" : "false");
    }
    printf("\n],\"cases\":10,\"unsafe_callback_mmio\":%d}\n", total_unsafe);
    return 0;
}
'''


def main():
    sources = {'port': (ROOT / PATH).read_text()}
    for label, ref in [('native', LTS), ('ack_control', ACK)]:
        sources[label] = subprocess.check_output(['git', 'show', ref + ':' + PATH], cwd=ROOT, text=True)
    results = {}
    with tempfile.TemporaryDirectory(prefix='xhci-reset-hooks-') as tmp:
        for label, text in sources.items():
            body = function(text, 'xhci_reset')
            src = Path(tmp) / (label + '.c')
            exe = Path(tmp) / label
            src.write_text(PRE + body + MAIN)
            cmd = ['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                   '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
                   '-DHAS_HOOKS=' + ('0' if label == 'native' else '1'), str(src), '-o', str(exe)]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            result = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
            assert not result.stderr, result.stderr
            results[label] = dict(function_sha256=hashlib.sha256(body.encode()).hexdigest(), **json.loads(result.stdout))
    fields = ('case', 'return', 'events', 'command', 'bus_cleared')
    for p, n in zip(results['port']['observations'], results['native']['observations']):
        assert all(p[k] == n[k] for k in fields), (p, n)
    assert results['port']['unsafe_callback_mmio'] == 0
    assert results['ack_control']['unsafe_callback_mmio'] == 3
    report = dict(source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  source_file_sha256=hashlib.sha256(sources['port'].encode()).hexdigest(),
                  native=LTS, ack=ACK, results=results,
                  validation='Ten scenarios per extracted function under ASan/UBSan. Port preserves native return values, register-operation/delay order and bus state. Actual ACK placement exposes INIT callback register access before the Intel delay in three scenarios.',
                  limitations='Register/time/lock-free callback shims, not real MMIO, USB hardware, kernel locking, emulator boot or concurrency testing.',
                  remote_sources_used=[])
    dest = ROOT / 'Documentation/android-port/evidence/xhci-reset-hooks-check.json'
    dest.write_text(json.dumps(report, indent=2) + '\n')
    print('10 port cases and 10 native cases passed; ACK control exposed 3 premature callback accesses')


if __name__ == '__main__':
    main()
