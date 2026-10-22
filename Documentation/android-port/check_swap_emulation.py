#!/usr/bin/env python3
"""Check extracted swap-header/map code with host I/O and allocation shims.

Exercises page units, native-header preference, private-copy/error handling,
endian conversion, limits, bad-page expansion and cluster/map reservations.
Also checks activation/deactivation accounting across hook changes.
Old-code controls reproduce quarter-capacity interpretation and erased magic
on header-read failure. No real swap device, kernel I/O or runtime is exercised.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
baseline = 'aa723abf2d0547fdddee6cc7e806da55cbd19d7b'

def read(path, old=False):
    if old:
        return subprocess.check_output(['git', 'show', baseline + ':' + path], cwd=root, text=True)
    return (root / path).read_text()

def function(text, name):
    start = text.index(name)
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end] + '\n'

current = read('mm/swapfile.c')
header = function(read('include/linux/swap.h'), 'union swap_header {').rstrip() + ';\n'
excerpts = [header, function(current, 'static union swap_header *read_swap_header_compat('),
            function(current, 'static unsigned long read_swap_header('),
            function(current, 'static int setup_swap_map('),
            function(read('mm/swapfile.c', True), 'static unsigned long read_swap_header(')
                .replace('read_swap_header(', 'old_read_swap_header(', 1),
            function(read('mm/page_size_compat.c', True), 'int __fixup_swap_header(')]
cluster = current.split('static struct swap_cluster_info *setup_clusters(', 1)[1]
cluster = cluster[cluster.index('\tfor (i = 0; i < header_pages; i++)'):cluster.index('\tINIT_LIST_HEAD(&si->free_clusters);')]
excerpts.append(cluster)
def rotation_code(text, prefix):
    on = text.split('SYSCALL_DEFINE2(swapon,', 1)[1]
    on = on[on.index('\tif (si->bdev && !hibernation_swap'):on.index('\n\tcluster_info = setup_clusters(')]
    off = text.split('SYSCALL_DEFINE1(swapoff,', 1)[1].splitlines()
    index = next(i for i, line in enumerate(off) if 'atomic_dec(&nr_rotate_swap)' in line)
    return ('static void ' + prefix + '_on(struct swap_info_struct *si, bool hibernation_swap) {\n'
            'bool inced_nr_rotate_swap = false;\n' + on + '\n(void)inced_nr_rotate_swap;\n}\n'
            'static void ' + prefix + '_off(struct swap_info_struct *p, bool hibernation_swap) {\n' +
            '\n'.join(off[index - 1:index + 1]) + '\n}\n')
rotation = rotation_code(current, 'new') + rotation_code(read('mm/swapfile.c', True), 'old')
excerpts.append(rotation)
shim = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
typedef uint32_t __u32;
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
static unsigned int page_shift;
#define __PAGE_SHIFT page_shift
#define __PAGE_SIZE (1UL << page_shift)
#define min(a,b) ((a) < (b) ? (a) : (b))
#define round_up(n,d) (((n) + (d) - 1) & ~((d) - 1))
#define SWAPFILE_CLUSTER 16UL
#define GFP_KERNEL 0
#define SWAP_MAP_BAD 63
#define pr_err(...) do {} while (0)
#define pr_warn(...) do {} while (0)
#define pgcompat_err(...) do {} while (0)
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(e) ((void *)(long)(e))
#define ERR_CAST(p) ((void *)(p))
#define K(n) ((n) << (PAGE_SHIFT - 10))
static unsigned long swapfile_maximum_size;
struct inode { unsigned int i_mode; uint64_t size; };
struct file { int unused; };
struct address_space { int unused; };
struct block_device { bool nonrot; };
#define SWP_SOLIDSTATE (1UL << 4)
struct swap_info_struct { unsigned int pages; unsigned long flags; struct block_device *bdev; };
static int nr_rotate_swap;
static bool bdev_nonrot(struct block_device *bdev) { return bdev->nonrot; }
static void atomic_inc(int *p) { (*p)++; }
static void atomic_dec(int *p) { (*p)--; }
struct swap_cluster_info { unsigned char reserved[256]; };
static uint32_t swab32(uint32_t value) { return __builtin_bswap32(value); }
static void swab32s(uint32_t *value) { *value = swab32(*value); }
static uint64_t i_size_read(struct inode *inode) { return inode->size; }
'''
io_shim = r'''
#define MAX_SWAP_BADPAGES ((offsetof(union swap_header, magic.magic) - \
                          offsetof(union swap_header, info.badpages)) / sizeof(int))
struct page { union swap_header header; int refs; };
static struct page pages[4];
static int fail_page, read_calls, allocations;
static bool fail_alloc;
static struct page *read_mapping_page(struct address_space *mapping, int index, struct file *file) {
    (void)mapping; (void)file; assert(index >= 0 && index < 4); read_calls++;
    if (index == fail_page) return ERR_PTR(-EIO);
    pages[index].refs++; return &pages[index];
}
static void *kmap_local_page(struct page *page) { return &page->header; }
static void kunmap_local(void *p) { (void)p; }
static void *kmap(struct page *page) { return &page->header; }
static void kunmap(struct page *page) { (void)page; }
static void put_page(struct page *page) { assert(page->refs > 0); page->refs--; }
static void *kmemdup(const void *data, size_t size, int flags) {
    (void)flags; if (fail_alloc) return NULL;
    void *p = malloc(size); assert(p); memcpy(p, data, size); allocations++; return p;
}
static void kfree(void *p) { if (p) { assert(allocations > 0); allocations--; free(p); } }
static int inc_cluster_info_page(struct swap_info_struct *si, struct swap_cluster_info *ci,
                                 unsigned long page) {
    (void)si; assert(page < sizeof(ci->reserved)); ci->reserved[page]++; return 0;
}
static void reset(unsigned int shift, unsigned int units, bool big_endian) {
    assert(allocations == 0);
    for (unsigned int i = 0; i < 4; i++) assert(pages[i].refs == 0);
    memset(pages, 0, sizeof(pages));
    page_shift = shift; fail_page = -1; fail_alloc = false; read_calls = 0;
    swapfile_maximum_size = ULONG_MAX >> 12;
    pages[0].header.info.version = big_endian ? swab32(1) : 1;
    pages[0].header.info.last_page = big_endian ? swab32(units - 1) : units - 1;
    memcpy(pages[(1U << (shift - PAGE_SHIFT)) - 1].header.magic.magic, "SWAPSPACE2", 10);
}
'''
cluster_function = '''static int mark_clusters(struct swap_info_struct *si, union swap_header *swap_header,
    struct swap_cluster_info *cluster_info, unsigned long maxpages, unsigned int header_pages) {
    unsigned long i; int err;
''' + cluster + 'return 0;\nerr:\nreturn err;\n}\n'
checks = r'''
int main(void) {
    struct address_space mapping; struct file file;
    struct inode inode = { .i_mode = S_IFBLK };
    struct swap_info_struct si;
    unsigned char map[256];
    for (unsigned int shift = 12; shift <= 14; shift++) {
        unsigned int nr = 1U << (shift - PAGE_SHIFT);
        for (int big = 0; big < 2; big++) {
            reset(shift, 16, big); inode.size = 16UL * __PAGE_SIZE;
            union swap_header before = pages[0].header;
            unsigned int header_pages = 99;
            union swap_header *copy = read_swap_header_compat(&file, &mapping, &pages[0].header, &header_pages);
            assert(!IS_ERR(copy) && header_pages == nr && (copy != NULL) == (nr > 1));
            union swap_header *h = copy ? copy : &pages[0].header;
            unsigned long max = read_swap_header(&si, h, &inode, header_pages);
            assert(max == 16 * nr);
            si.pages = max - 1; memset(map, 0, sizeof(map));
            assert(setup_swap_map(&si, h, map, max, header_pages) == 0);
            assert(si.pages == 15 * nr);
            for (unsigned int i = 0; i < max; i++) assert(map[i] == (i < nr ? SWAP_MAP_BAD : 0));
            struct swap_cluster_info ci = {};
            assert(mark_clusters(&si, h, &ci, max, header_pages) == 0);
            for (unsigned int i = 0; i < max; i++) assert(!!ci.reserved[i] == !!map[i]);
            if (nr > 1) {
                assert(memcmp(&before, &pages[0].header, sizeof(before)) == 0);
                assert(!memcmp(pages[nr - 1].header.magic.magic, "SWAPSPACE2", 10));
                assert(old_read_swap_header(&si, h, &inode) == 16); /* undersized swap */
            }
            h->info.nr_badpages = 1; h->info.badpages[0] = 2;
            si.pages = max - 1; memset(map, 0, sizeof(map)); memset(&ci, 0, sizeof(ci));
            assert(setup_swap_map(&si, h, map, max, header_pages) == 0);
            assert(si.pages == 14 * nr);
            assert(mark_clusters(&si, h, &ci, max, header_pages) == 0);
            for (unsigned int i = 0; i < max; i++) {
                assert(!!map[i] == (i < nr || (i >= 2 * nr && i < 3 * nr)));
                assert(!!ci.reserved[i] == !!map[i]);
            }
            inode.i_mode = S_IFREG;
            assert(read_swap_header(&si, h, &inode, header_pages) == 0);
            inode.i_mode = S_IFBLK; h->info.badpages[0] = 16;
            assert(setup_swap_map(&si, h, map, max, header_pages) == -EINVAL);
            h->info.nr_badpages = MAX_SWAP_BADPAGES + 1;
            assert(read_swap_header(&si, h, &inode, header_pages) == 0);
            h->info.nr_badpages = 0; h->info.version = 2;
            assert(read_swap_header(&si, h, &inode, header_pages) == 0);
            h->info.version = 1; inode.size = PAGE_SIZE;
            assert(read_swap_header(&si, h, &inode, header_pages) == 0);
            inode.size = 0; h->info.last_page = UINT_MAX - 1;
            assert(read_swap_header(&si, h, &inode, header_pages) == (nr > 1 ? UINT_MAX : UINT_MAX - 0UL));
            h->info.last_page = UINT_MAX;
            assert(read_swap_header(&si, h, &inode, header_pages) == UINT_MAX);
            kfree(copy);
        }
        if (nr == 1) continue;
        reset(shift, 16, false); unsigned int header_pages;
        union swap_header first = pages[0].header, last = pages[nr - 1].header;
        fail_alloc = true;
        assert(PTR_ERR(read_swap_header_compat(&file, &mapping, &first, &header_pages)) == -ENOMEM);
        assert(header_pages == 1 && !memcmp(&last, &pages[nr - 1].header, sizeof(last)));
        fail_alloc = false; fail_page = nr - 1;
        assert(PTR_ERR(read_swap_header_compat(&file, &mapping, &first, &header_pages)) == -EIO);
        assert(!memcmp(&last, &pages[nr - 1].header, sizeof(last)));
        memcpy(first.magic.magic, "SWAPSPACE2", 10); read_calls = 0;
        assert(read_swap_header_compat(&file, &mapping, &first, &header_pages) == NULL);
        assert(header_pages == 1 && read_calls == 0); /* native format preferred */
        reset(shift, 16, false); fail_page = 0;
        assert(__fixup_swap_header(&file, &mapping) == -EIO);
        assert(memcmp(pages[nr - 1].header.magic.magic, "SWAPSPACE2", 10));
    }
    reset(12, 16, false);
    struct block_device bdev;
    for (int present = 0; present < 2; present++)
    for (int nonrot = 0; nonrot < 2; nonrot++)
    for (int on_hib = 0; on_hib < 2; on_hib++)
    for (int off_hib = 0; off_hib < 2; off_hib++)
    for (int old_flag = 0; old_flag < 2; old_flag++) {
        bdev.nonrot = nonrot; si.bdev = present ? &bdev : NULL;
        si.flags = old_flag ? SWP_SOLIDSTATE : 0; nr_rotate_swap = 0;
        new_on(&si, on_hib);
        new_off(&si, off_hib);
        assert(nr_rotate_swap == 0);
    }
    si.bdev = &bdev; bdev.nonrot = true; si.flags = 0; nr_rotate_swap = 0;
    old_on(&si, true); old_off(&si, false);
    assert(nr_rotate_swap == 1); /* changing hook loses the decrement */
    puts("Swap emulation header/capacity/map/cluster checks passed; old capacity and erased-magic controls reproduced");
}
'''
program = shim + excerpts[0] + io_shim + ''.join(excerpts[1:-2]) + cluster_function + rotation + checks
with tempfile.TemporaryDirectory(prefix='swap-emulation-check-') as tmp:
    src = Path(tmp) / 'check.c'; binary = Path(tmp) / 'check'
    src.write_text(program)
    options = ['-std=gnu11', '-Wall', '-Wextra', '-Wno-unused-parameter', '-Wno-sign-compare',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(['cc', *options, str(src), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise SystemExit(result.stderr or result.stdout)
record = {
    'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'negative_control_commit': baseline,
    'excerpts_sha256': hashlib.sha256(''.join(excerpts).encode()).hexdigest(),
    'compiler': subprocess.check_output(['cc', '--version'], text=True).splitlines()[0],
    'compiler_flags': options,
    'result': result.stdout.strip(),
    'scope': __doc__.strip(),
}
a.output.write_text(json.dumps(record, indent=2) + '\n')
print(record['result'])
