#include <linux/zram_ioctl.h>
#define OFF(t,f) __builtin_offsetof(struct t,f)
_Static_assert(sizeof(struct zram_android_ioc_data)==16,"legacy size");
_Static_assert(sizeof(struct zram_android_ioc_process_range_writeback)==40,"range size");
_Static_assert(sizeof(struct zram_android_ioc_process_prefetch)==8,"prefetch size");
_Static_assert(OFF(zram_android_ioc_process_range_writeback,pidfd)==0,"pidfd");
_Static_assert(OFF(zram_android_ioc_process_range_writeback,start_addr)==8,"start");
_Static_assert(OFF(zram_android_ioc_process_range_writeback,size)==16,"size");
_Static_assert(OFF(zram_android_ioc_process_range_writeback,next_addr)==24,"next");
_Static_assert(OFF(zram_android_ioc_process_range_writeback,written_bytes)==32,"written");
_Static_assert(ZRAM_ANDROID_IOC_PROCESS_WRITEBACK==0xc010bb01,"legacy command");
_Static_assert(ZRAM_ANDROID_IOC_PROCESS_RANGE_WRITEBACK==0xc028bb02,"range command");
_Static_assert(ZRAM_ANDROID_IOC_PROCESS_PREFETCH==0x4008bb03,"prefetch command");
_Static_assert(ZRAM_ANDROID_IOC_GET_VERSION==0xbb04,"version command");
