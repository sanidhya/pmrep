#ifndef __ARCH_H_
#define __ARCH_H_

#include <stdint.h>
#include <time.h>

#define L1D_CACHELINE_BYTES     (64)
#define FLUSH_ALIGN             L1D_CACHELINE_BYTES
#define L1D_CACHELINE_BYTES2    (128)
#define MAX_CPU                 (256)
#define PAGE_SIZE               (4096)

#define ____cacheline_aligned   __attribute__ ((aligned (L1D_CACHELINE_BYTES)))

static inline void smp_rmb(void)
{
    __asm __volatile("lfence":::"memory");
}

static inline void smp_wmb(void)
{
    __asm __volatile("sfence":::"memory");
}

static inline void smp_mb(void)
{
    __asm __volatile("mfence":::"memory");
}

static inline void smp_cmb(void)
{
    __asm __volatile("":::"memory");
}

#define smp_wmb_tso()       smp_cmb()

/* Compiler hints */
#define likely(x)   __builtin_expect((long int)(x),1)
#define unlikely(x) __builtin_expect((long int)(x),0)

/*
 * atomic opeartions
 */
#define smp_cas(__ptr, __old_val, __new_val)	\
	__sync_bool_compare_and_swap(__ptr, __old_val, __new_val)

#define smp_swap(__ptr, __val)			\
	__sync_lock_test_and_set(__ptr, __val)

#define smp_faa(__ptr, __val)			\
	__sync_fetch_and_add(__ptr, __val)

#define smp_prefetchr(__ptr)			\
	__builtin_prefetch((void*)__ptr, 0, 3)

#define smp_prefetchw(__ptr)			\
	__builtin_prefetch((void*)__ptr, 1, 3)

static inline void nop_pause(void)
{
    __asm __volatile("pause");
}

static inline void rep_nop(void)
{
    __asm __volatile("rep; nop" ::: "memory");
}

static inline void cpu_relax(void)
{
    rep_nop();
}

#define nsecs(v) ((v).tv_sec * 1000000000 + (v).tv_nsec)

static inline uint64_t get_time(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return nsecs(tp);
}

/* Flush options */
#define clflushopt(addr) \
    asm volatile(".byte 0x66; clflush %0" : "+m" (*(volatile char *)addr))
#define	clwb(addr)          \
	asm volatile(".byte 0x66; xsaveopt %0" : "+m" (*(volatile char *)addr))

#define	pcommit() asm volatile(".byte 0x66, 0x0f, 0xae, 0xf8")

/* Range based flushing */
#define	clflush_range(addr, len)                            \
do {                                                        \
        uintptr_t ptr;                                      \
        for (ptr = (uintptr_t)addr & ~(FLUSH_ALIGN - 1);    \
             ptr < (uintptr_t)addr + len;                   \
             ptr += FLUSH_ALIGN)                            \
            clflushopt((char *)ptr);                        \
} while (0)

#define	clwb_range(addr, len)                               \
do {                                                        \
        uintptr_t ptr;                                      \
        for (ptr = (uintptr_t)addr & ~(FLUSH_ALIGN - 1);    \
             ptr < (uintptr_t)addr + len;                   \
             ptr += FLUSH_ALIGN)                            \
            clwb((char *)ptr);                              \
} while (0)

#endif /* __ARCH_H_ */
