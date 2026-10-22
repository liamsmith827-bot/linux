#!/usr/bin/env python3
"""Exercise the actual UID range-removal function with a host-side hash-table shim.

This checks range validation, endpoint selection, and bounded bucket visits. It
is not a kernel locking, SELinux, userspace integration, or runtime test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
source = root / 'drivers/misc/uid_sys_stats.c'
text = source.read_text()
function = text.split('static ssize_t uid_remove_write(', 1)[1].split(
    '\nstatic const struct proc_ops uid_remove_fops', 1)[0]
function = 'static ssize_t uid_remove_write(' + function
shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint32_t u32;
#define __user
#define BUCKETS 1024
struct file { int unused; };
struct uid_entry;
struct hlist_node { struct uid_entry *next; struct uid_entry **prev; };
struct uid_entry { unsigned int uid; struct hlist_node hash; };
static struct uid_entry *table[BUCKETS];
static int held = -1, fault;
static unsigned int visits, reschedules, live;
#define for_each_bkt(bkt) for ((bkt) = 0; (bkt) < BUCKETS; (bkt)++)
#define for_each_uid_entry_safe(e, tmp, bkt) \
    for ((e) = table[bkt]; (e) && ((tmp) = (struct hlist_node *)(e)->hash.next, 1); \
         (e) = (struct uid_entry *)(tmp))
static void lock_uid_by_bkt(u32 bkt) {
    assert(held == -1); held = bkt; visits++;
}
static void unlock_uid_by_bkt(u32 bkt) { assert(held == (int)bkt); held = -1; }
static void hash_del(struct hlist_node *n) {
    assert(held >= 0); *n->prev = n->next;
    if (n->next) n->next->hash.prev = n->prev;
}
static void kfree(void *p) { assert(live); live--; free(p); }
static void cond_resched(void) { assert(held == -1); reschedules++; }
static int copy_from_user(void *to, const void *from, size_t n) {
    if (fault) return 1;
    memcpy(to, from, n); return 0;
}
static int kstrtol(const char *s, unsigned int base, long *result) {
    char *end;
    errno = 0; *result = strtol(s, &end, base);
    if (errno || end == s) return -EINVAL;
    if (*end == '\n') end++;
    return *end ? -EINVAL : 0;
}
static void add(unsigned int uid) {
    unsigned int b = uid % BUCKETS;
    struct uid_entry *e = calloc(1, sizeof(*e));
    assert(e); live++; e->uid = uid; e->hash.next = table[b];
    e->hash.prev = &table[b];
    if (table[b]) table[b]->hash.prev = &e->hash.next;
    table[b] = e;
}
static int has(unsigned int uid) {
    struct uid_entry *e;
    for (e = table[uid % BUCKETS]; e; e = e->hash.next)
        if (e->uid == uid) return 1;
    return 0;
}
'''
checks = r'''
static ssize_t request(const char *s) {
    visits = reschedules = 0;
    return uid_remove_write(NULL, s, strlen(s), NULL);
}
int main(void) {
    const char *bad[] = {"", "-1-2", "2-1", "0-4294967296", "0-9223372036854775807",
                         "0-9223372036854775808", "1", "x-2", "1-2junk"};
    add(0); add(1); add(2); add(1025); add(1026); add(UINT_MAX);
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(request(bad[i]) == -EINVAL);
        assert(live == 6 && visits == 0 && reschedules == 0);
    }
    fault = 1; assert(request("0-1") == -EFAULT); fault = 0;
    assert(live == 6 && visits == 0);
    assert(request("1-1025") == 6);
    assert(live == 3 && has(0) && has(1026) && has(UINT_MAX));
    assert(!has(1) && !has(2) && !has(1025));
    assert(visits == BUCKETS && reschedules == BUCKETS);
    assert(request("4294967295-4294967295\n") == 22);
    assert(live == 2 && !has(UINT_MAX));
    assert(request("0-4294967295") == 12);
    assert(live == 0 && visits == BUCKETS && reschedules == BUCKETS);
    assert(request("0-4294967295") == 12);
    assert(live == 0 && visits == BUCKETS && reschedules == BUCKETS && held == -1);
    puts("UID range checks passed");
}
'''
with tempfile.TemporaryDirectory(prefix='uid-range-check-') as tmp:
    c = Path(tmp) / 'check.c'
    binary = Path(tmp) / 'check'
    c.write_text(shim + function + checks)
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Wno-unused-parameter',
             '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(['cc', *flags, str(c), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=5)
record = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'function_sha256': hashlib.sha256(function.encode()).hexdigest(),
    'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
    'compiler_flags': flags,
    'checks': ['invalid syntax and signed/unsigned boundaries', 'copy failure leaves table intact',
               'inclusive endpoints and colliding bucket entries', 'maximum UID singleton',
               'entire UID range on populated and empty tables', '1024 bucket visits regardless of range'],
    'result': result.stdout.strip(),
    'scope': __doc__.strip(),
}
args.output.write_text(json.dumps(record, indent=2) + '\n')
print(record['result'])
