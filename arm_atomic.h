#ifndef __ARM_ATOMIC_H__
#define __ARM_ATOMIC_H__
#include <unistd.h>
#include <sys/syscall.h>

#include <errno.h>
//arm 64 原子操作头文件，注意仅能用于arm64平台，不支持32位平台，尽量使用汇编实现，但也会使用gcc内置函数实现
//代码来源于DPDK
//包括以下几个部分：
//1.内存屏障
//2.原子操作
//3.pause,用于短时间等待的情况，和wait until
//4.prefetch
//5.rwlock


/**
 * Force a function to be __pacc_always_inlined
 */
#define __pacc_always_inline inline __attribute__((always_inline))

/**
 * Hint function in the hot path
 */
#define __pacc_hot __attribute__((hot))

/**
 * Hint function in the cold path
 */
#define __pacc_cold __attribute__((cold))

#define __pacc_warn_unused_result __attribute__((warn_unused_result))


//内存屏障
#define pacc_mb() asm volatile("dmb osh" : : : "memory")

#define pacc_wmb() asm volatile("dmb oshst" : : : "memory")

#define pacc_rmb() asm volatile("dmb oshld" : : : "memory")

#define pacc_smp_mb() asm volatile("dmb ish" : : : "memory")

#define pacc_smp_wmb() asm volatile("dmb ishst" : : : "memory")

#define pacc_smp_rmb() asm volatile("dmb ishld" : : : "memory")

#define pacc_io_mb() pacc_mb()

#define pacc_io_wmb() pacc_wmb()

#define pacc_io_rmb() pacc_rmb()

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef signed long int int64_t;
typedef unsigned long int uint64_t;


static __pacc_always_inline void
pacc_atomic_thread_fence(int memorder)
{
    __atomic_thread_fence(memorder);
}

//原子操作，采用gcc内置函数实现

/**
 * Compiler barrier.
 *
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define pacc_compiler_barrier() do {        \
    asm volatile ("" : : : "memory");   \
} while(0)

/**
 * Synchronization fence between threads based on the specified memory order.
 */
static __pacc_always_inline void pacc_atomic_thread_fence(int memorder);

/*------------------------- 16 bit atomic operations -------------------------*/

/**
 * Atomic compare and set.
 *
 * (atomic) equivalent to:
 *   if (*dst == exp)
 *     *dst = src (all 16-bit words)
 *
 * @param dst
 *   The destination location into which the value will be written.
 * @param exp
 *   The expected value.
 * @param src
 *   The new value.
 * @return
 *   Non-zero on success; 0 on failure.
 */

static __pacc_always_inline int
pacc_atomic16_cmpset(volatile uint16_t *dst, uint16_t exp, uint16_t src)
{
    return __sync_bool_compare_and_swap(dst, exp, src);
}

/**
 * Atomic exchange.
 *
 * (atomic) equivalent to:
 *   ret = *dst
 *   *dst = val;
 *   return ret;
 *
 * @param dst
 *   The destination location into which the value will be written.
 * @param val
 *   The new value.
 * @return
 *   The original value at that location
 */
static __pacc_always_inline uint16_t
pacc_atomic16_exchange(volatile uint16_t *dst, uint16_t val)
{
#if defined(__clang__)
    return __atomic_exchange_n(dst, val, __ATOMIC_SEQ_CST);
#else
    return __atomic_exchange_2(dst, val, __ATOMIC_SEQ_CST);
#endif
}


/**
 * The atomic counter structure.
 */
typedef struct {
    volatile int16_t cnt; /**< An pacc counter value. */
} pacc_atomic16_t;

/**
 * Static initializer for an atomic counter.
 */
#define RTE_ATOMIC16_INIT(val) { (val) }

/**
 * Initialize an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void
pacc_atomic16_init(pacc_atomic16_t *v)
{
    v->cnt = 0;
}

/**
 * Atomically read a 16-bit value from a counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   The value of the counter.
 */
static __pacc_always_inline int16_t
pacc_atomic16_read(const pacc_atomic16_t *v)
{
    return v->cnt;
}

/**
 * Atomically set a counter to a 16-bit value.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param new_value
 *   The new value for the counter.
 */
static __pacc_always_inline void
pacc_atomic16_set(pacc_atomic16_t *v, int16_t new_value)
{
    v->cnt = new_value;
}

/**
 * Atomically add a 16-bit value to an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 */
static __pacc_always_inline void
pacc_atomic16_add(pacc_atomic16_t *v, int16_t inc)
{
    __sync_fetch_and_add(&v->cnt, inc);
}

/**
 * Atomically subtract a 16-bit value from an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 */
static __pacc_always_inline void
pacc_atomic16_sub(pacc_atomic16_t *v, int16_t dec)
{
    __sync_fetch_and_sub(&v->cnt, dec);
}

/**
 * Atomically increment a counter by one.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void
pacc_atomic16_inc(pacc_atomic16_t *v)
{
    pacc_atomic16_add(v, 1);
}

/**
 * Atomically decrement a counter by one.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void
pacc_atomic16_dec(pacc_atomic16_t *v)
{
    pacc_atomic16_sub(v, 1);
}

/**
 * Atomically add a 16-bit value to a counter and return the result.
 *
 * Atomically adds the 16-bits value (inc) to the atomic counter (v) and
 * returns the value of v after addition.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 * @return
 *   The value of v after the addition.
 */
static __pacc_always_inline int16_t
pacc_atomic16_add_return(pacc_atomic16_t *v, int16_t inc)
{
    return __sync_add_and_fetch(&v->cnt, inc);
}

/**
 * Atomically subtract a 16-bit value from a counter and return
 * the result.
 *
 * Atomically subtracts the 16-bit value (inc) from the atomic counter
 * (v) and returns the value of v after the subtraction.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 * @return
 *   The value of v after the subtraction.
 */
static __pacc_always_inline int16_t
pacc_atomic16_sub_return(pacc_atomic16_t *v, int16_t dec)
{
    return __sync_sub_and_fetch(&v->cnt, dec);
}

/**
 * Atomically increment a 16-bit counter by one and test.
 *
 * Atomically increments the atomic counter (v) by one and returns true if
 * the result is 0, or false in all other cases.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   True if the result after the increment operation is 0; false otherwise.
 */
static __pacc_always_inline int pacc_atomic16_inc_and_test(pacc_atomic16_t *v)
{
    return __sync_add_and_fetch(&v->cnt, 1) == 0;
}


/**
 * Atomically decrement a 16-bit counter by one and test.
 *
 * Atomically decrements the atomic counter (v) by one and returns true if
 * the result is 0, or false in all other cases.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   True if the result after the decrement operation is 0; false otherwise.
 */
static __pacc_always_inline int pacc_atomic16_dec_and_test(pacc_atomic16_t *v)
{
    return __sync_sub_and_fetch(&v->cnt, 1) == 0;
}


/**
 * Atomically test and set a 16-bit atomic counter.
 *
 * If the counter value is already set, return 0 (failed). Otherwise, set
 * the counter value to 1 and return 1 (success).
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   0 if failed; else 1, success.
 */
static __pacc_always_inline int pacc_atomic16_test_and_set(pacc_atomic16_t *v)
{
    return pacc_atomic16_cmpset((volatile uint16_t *)&v->cnt, 0, 1);
}

/**
 * Atomically set a 16-bit counter to 0.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void pacc_atomic16_clear(pacc_atomic16_t *v)
{
    v->cnt = 0;
}

/*------------------------- 32 bit atomic operations -------------------------*/

/**
 * Atomic compare and set.
 *
 * (atomic) equivalent to:
 *   if (*dst == exp)
 *     *dst = src (all 32-bit words)
 *
 * @param dst
 *   The destination location into which the value will be written.
 * @param exp
 *   The expected value.
 * @param src
 *   The new value.
 * @return
 *   Non-zero on success; 0 on failure.
 */
static __pacc_always_inline int
pacc_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
    return __sync_bool_compare_and_swap(dst, exp, src);
}

/**
 * Atomic exchange.
 *
 * (atomic) equivalent to:
 *   ret = *dst
 *   *dst = val;
 *   return ret;
 *
 * @param dst
 *   The destination location into which the value will be written.
 * @param val
 *   The new value.
 * @return
 *   The original value at that location
 */
static __pacc_always_inline uint32_t
pacc_atomic32_exchange(volatile uint32_t *dst, uint32_t val)
{
#if defined(__clang__)
    return __atomic_exchange_n(dst, val, __ATOMIC_SEQ_CST);
#else
    return __atomic_exchange_4(dst, val, __ATOMIC_SEQ_CST);
#endif
}


/**
 * The atomic counter structure.
 */
typedef struct {
    volatile int32_t cnt; /**< An pacc counter value. */
} pacc_atomic32_t;

/**
 * Static initializer for an atomic counter.
 */
#define RTE_ATOMIC32_INIT(val) { (val) }

/**
 * Initialize an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void
pacc_atomic32_init(uint32_t *v)
{
    *v = 0;
}

/**
 * Atomically read a 32-bit value from a counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   The value of the counter.
 */
static __pacc_always_inline uint32_t
pacc_atomic32_read(const uint32_t *v)
{
    return *v;
}

/**
 * Atomically set a counter to a 32-bit value.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param new_value
 *   The new value for the counter.
 */
static __pacc_always_inline void
pacc_atomic32_set(uint32_t *v, uint32_t new_value)
{
    *v = new_value;
}

/**
 * Atomically add a 32-bit value to an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 */
static __pacc_always_inline void
pacc_atomic32_add(uint32_t *v, uint32_t inc)
{
    __sync_fetch_and_add(v, inc);
}

/**
 * Atomically subtract a 32-bit value from an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 */
static __pacc_always_inline void
pacc_atomic32_sub(uint32_t *v, uint32_t dec)
{
    __sync_fetch_and_sub(v, dec);
}

/**
 * Atomically increment a counter by one.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void
pacc_atomic32_inc(uint32_t *v)
{
    pacc_atomic32_add(v, 1);
}

/**
 * Atomically decrement a counter by one.
 *
 * @param v
 *   A pointer to the atomic counter.
 */

static __pacc_always_inline void
pacc_atomic32_dec(uint32_t *v)
{
    pacc_atomic32_sub(v,1);
}

/**
 * Atomically add a 32-bit value to a counter and return the result.
 *
 * Atomically adds the 32-bits value (inc) to the atomic counter (v) and
 * returns the value of v after addition.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 * @return
 *   The value of v after the addition.
 */
static __pacc_always_inline uint32_t
pacc_atomic32_add_return(uint32_t *v, uint32_t inc)
{
    return __sync_add_and_fetch(v, inc);
}

/**
 * Atomically subtract a 32-bit value from a counter and return
 * the result.
 *
 * Atomically subtracts the 32-bit value (inc) from the atomic counter
 * (v) and returns the value of v after the subtraction.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 * @return
 *   The value of v after the subtraction.
 */
static __pacc_always_inline uint32_t
pacc_atomic32_sub_return(uint32_t *v, uint32_t dec)
{
    return __sync_sub_and_fetch(v, dec);
}

/**
 * Atomically increment a 32-bit counter by one and test.
 *
 * Atomically increments the atomic counter (v) by one and returns true if
 * the result is 0, or false in all other cases.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   True if the result after the increment operation is 0; false otherwise.
 */
static __pacc_always_inline int pacc_atomic32_inc_and_test(uint32_t *v)
{
    return __sync_add_and_fetch(v, 1) == 0;
}


/**
 * Atomically decrement a 32-bit counter by one and test.
 *
 * Atomically decrements the atomic counter (v) by one and returns true if
 * the result is 0, or false in all other cases.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   True if the result after the decrement operation is 0; false otherwise.
 */
static __pacc_always_inline int pacc_atomic32_dec_and_test(uint32_t *v)
{
    return __sync_sub_and_fetch(v, 1) == 0;
}

/**
 * Atomically test and set a 32-bit atomic counter.
 *
 * If the counter value is already set, return 0 (failed). Otherwise, set
 * the counter value to 1 and return 1 (success).
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   0 if failed; else 1, success.
 */
static __pacc_always_inline int pacc_atomic32_test_and_set(uint32_t *v)
{
    return pacc_atomic32_cmpset((volatile uint32_t *)v, 0, 1);
}

/**
 * Atomically set a 32-bit counter to 0.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void pacc_atomic32_clear(uint32_t *v)
{
    *v= 0;
}

/*------------------------- 64 bit atomic operations -------------------------*/

/**
 * An atomic compare and set function used by the mutex functions.
 * (atomic) equivalent to:
 *   if (*dst == exp)
 *     *dst = src (all 64-bit words)
 *
 * @param dst
 *   The destination into which the value will be written.
 * @param exp
 *   The expected value.
 * @param src
 *   The new value.
 * @return
 *   Non-zero on success; 0 on failure.
 */
static __pacc_always_inline int
pacc_atomic64_cmpset(volatile uint64_t *dst, uint64_t exp, uint64_t src)
{
    return __sync_bool_compare_and_swap(dst, exp, src);
}

/**
 * Atomic exchange.
 *
 * (atomic) equivalent to:
 *   ret = *dst
 *   *dst = val;
 *   return ret;
 *
 * @param dst
 *   The destination location into which the value will be written.
 * @param val
 *   The new value.
 * @return
 *   The original value at that location
 */
static __pacc_always_inline uint64_t
pacc_atomic64_exchange(volatile uint64_t *dst, uint64_t val)
{
#if defined(__clang__)
    return __atomic_exchange_n(dst, val, __ATOMIC_SEQ_CST);
#else
    return __atomic_exchange_8(dst, val, __ATOMIC_SEQ_CST);
#endif
}


/**
 * The atomic counter structure.
 */
typedef struct {
    volatile int64_t cnt;  /**< Internal counter value. */
} pacc_atomic64_t;

/**
 * Static initializer for an atomic counter.
 */
#define RTE_ATOMIC64_INIT(val) { (val) }

/**
 * Initialize the atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void
pacc_atomic64_init(pacc_atomic64_t *v)
{
#ifdef __LP64__
    v->cnt = 0;
#else
    int success = 0;
    uint64_t tmp;

    while (success == 0) {
        tmp = v->cnt;
        success = pacc_atomic64_cmpset((volatile uint64_t *)&v->cnt,
                                      tmp, 0);
    }
#endif
}


/**
 * Atomically read a 64-bit counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   The value of the counter.
 */
static __pacc_always_inline int64_t
pacc_atomic64_read(pacc_atomic64_t *v)
{
#ifdef __LP64__
    return v->cnt;
#else
    int success = 0;
    uint64_t tmp;

    while (success == 0) {
        tmp = v->cnt;
        /* replace the value by itself */
        success = pacc_atomic64_cmpset((volatile uint64_t *)&v->cnt,
                                      tmp, tmp);
    }
    return tmp;
#endif
}


/**
 * Atomically set a 64-bit counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param new_value
 *   The new value of the counter.
 */
static __pacc_always_inline void
pacc_atomic64_set(pacc_atomic64_t *v, int64_t new_value)
{
#ifdef __LP64__
    v->cnt = new_value;
#else
    int success = 0;
    uint64_t tmp;

    while (success == 0) {
        tmp = v->cnt;
        success = pacc_atomic64_cmpset((volatile uint64_t *)&v->cnt,
                                      tmp, new_value);
    }
#endif
}


/**
 * Atomically add a 64-bit value to a counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 */
static __pacc_always_inline void
pacc_atomic64_add(pacc_atomic64_t *v, int64_t inc)
{
    __sync_fetch_and_add(&v->cnt, inc);
}

/**
 * Atomically subtract a 64-bit value from a counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 */
static __pacc_always_inline void
pacc_atomic64_sub(pacc_atomic64_t *v, int64_t dec)
{
    __sync_fetch_and_sub(&v->cnt, dec);
}

/**
 * Atomically increment a 64-bit counter by one and test.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void
pacc_atomic64_inc(pacc_atomic64_t *v);

#ifdef RTE_FORCE_INTRINSICS
static __pacc_always_inline void
pacc_atomic64_inc(pacc_atomic64_t *v)
{
    pacc_atomic64_add(v, 1);
}
#endif

/**
 * Atomically decrement a 64-bit counter by one and test.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void
pacc_atomic64_dec(pacc_atomic64_t *v)
{
    pacc_atomic64_sub(v, 1);
}

/**
 * Add a 64-bit value to an atomic counter and return the result.
 *
 * Atomically adds the 64-bit value (inc) to the atomic counter (v) and
 * returns the value of v after the addition.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param inc
 *   The value to be added to the counter.
 * @return
 *   The value of v after the addition.
 */
static __pacc_always_inline int64_t
pacc_atomic64_add_return(pacc_atomic64_t *v, int64_t inc)
{
    return __sync_add_and_fetch(&v->cnt, inc);
}

/**
 * Subtract a 64-bit value from an atomic counter and return the result.
 *
 * Atomically subtracts the 64-bit value (dec) from the atomic counter (v)
 * and returns the value of v after the subtraction.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @param dec
 *   The value to be subtracted from the counter.
 * @return
 *   The value of v after the subtraction.
 */
static __pacc_always_inline int64_t
pacc_atomic64_sub_return(pacc_atomic64_t *v, int64_t dec)
{
    return __sync_sub_and_fetch(&v->cnt, dec);
}

/**
 * Atomically increment a 64-bit counter by one and test.
 *
 * Atomically increments the atomic counter (v) by one and returns
 * true if the result is 0, or false in all other cases.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   True if the result after the addition is 0; false otherwise.
 */
static __pacc_always_inline int pacc_atomic64_inc_and_test(pacc_atomic64_t *v)
{
    return pacc_atomic64_add_return(v, 1) == 0;
}


/**
 * Atomically decrement a 64-bit counter by one and test.
 *
 * Atomically decrements the atomic counter (v) by one and returns true if
 * the result is 0, or false in all other cases.
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   True if the result after subtraction is 0; false otherwise.
 */
static __pacc_always_inline int pacc_atomic64_dec_and_test(pacc_atomic64_t *v)
{
    return pacc_atomic64_sub_return(v, 1) == 0;
}

/**
 * Atomically test and set a 64-bit atomic counter.
 *
 * If the counter value is already set, return 0 (failed). Otherwise, set
 * the counter value to 1 and return 1 (success).
 *
 * @param v
 *   A pointer to the atomic counter.
 * @return
 *   0 if failed; else 1, success.
 */
static __pacc_always_inline int pacc_atomic64_test_and_set(pacc_atomic64_t *v)
{
    return pacc_atomic64_cmpset((volatile uint64_t *)&v->cnt, 0, 1);
}


/**
 * Atomically set a 64-bit counter to 0.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static __pacc_always_inline void pacc_atomic64_clear(pacc_atomic64_t *v)
{
    pacc_atomic64_set(v, 0);
}

//3. pause，用于节能
static __pacc_always_inline void pacc_pause(void)
{
    asm volatile("yield" ::: "memory");
}

/* Send an event to quit WFE. */
#define __RTE_ARM_SEVL() { asm volatile("sevl" : : : "memory"); }

/* Put processor into low power WFE(Wait For Event) state. */
#define __RTE_ARM_WFE() { asm volatile("wfe" : : : "memory"); }

/*
 * Atomic exclusive load from addr, it returns the 16-bit content of
 * *addr while making it 'monitored', when it is written by someone
 * else, the 'monitored' state is cleared and an event is generated
 * implicitly to exit WFE.
 */
#define __RTE_ARM_LOAD_EXC_16(src, dst, memorder) {       \
    if (memorder == __ATOMIC_RELAXED) {               \
        asm volatile("ldxrh %w[tmp], [%x[addr]]"  \
            : [tmp] "=&r" (dst)               \
            : [addr] "r" (src)                \
            : "memory");                      \
    } else {                                          \
        asm volatile("ldaxrh %w[tmp], [%x[addr]]" \
            : [tmp] "=&r" (dst)               \
            : [addr] "r" (src)                \
            : "memory");                      \
    } }

/*
 * Atomic exclusive load from addr, it returns the 32-bit content of
 * *addr while making it 'monitored', when it is written by someone
 * else, the 'monitored' state is cleared and an event is generated
 * implicitly to exit WFE.
 */
#define __RTE_ARM_LOAD_EXC_32(src, dst, memorder) {      \
    if (memorder == __ATOMIC_RELAXED) {              \
        asm volatile("ldxr %w[tmp], [%x[addr]]"  \
            : [tmp] "=&r" (dst)              \
            : [addr] "r" (src)               \
            : "memory");                     \
    } else {                                         \
        asm volatile("ldaxr %w[tmp], [%x[addr]]" \
            : [tmp] "=&r" (dst)              \
            : [addr] "r" (src)               \
            : "memory");                     \
    } }

/*
 * Atomic exclusive load from addr, it returns the 64-bit content of
 * *addr while making it 'monitored', when it is written by someone
 * else, the 'monitored' state is cleared and an event is generated
 * implicitly to exit WFE.
 */
#define __RTE_ARM_LOAD_EXC_64(src, dst, memorder) {      \
    if (memorder == __ATOMIC_RELAXED) {              \
        asm volatile("ldxr %x[tmp], [%x[addr]]"  \
            : [tmp] "=&r" (dst)              \
            : [addr] "r" (src)               \
            : "memory");                     \
    } else {                                         \
        asm volatile("ldaxr %x[tmp], [%x[addr]]" \
            : [tmp] "=&r" (dst)              \
            : [addr] "r" (src)               \
            : "memory");                     \
    } }

/*
 * Atomic exclusive load from addr, it returns the 128-bit content of
 * *addr while making it 'monitored', when it is written by someone
 * else, the 'monitored' state is cleared and an event is generated
 * implicitly to exit WFE.
 */
#define __RTE_ARM_LOAD_EXC_128(src, dst, memorder) {                    \
    volatile pacc_int128_t *dst_128 = (volatile pacc_int128_t *)&dst; \
    if (memorder == __ATOMIC_RELAXED) {                             \
        asm volatile("ldxp %x[tmp0], %x[tmp1], [%x[addr]]"      \
            : [tmp0] "=&r" (dst_128->val[0]),               \
              [tmp1] "=&r" (dst_128->val[1])                \
            : [addr] "r" (src)                              \
            : "memory");                                    \
    } else {                                                        \
        asm volatile("ldaxp %x[tmp0], %x[tmp1], [%x[addr]]"     \
            : [tmp0] "=&r" (dst_128->val[0]),               \
              [tmp1] "=&r" (dst_128->val[1])                \
            : [addr] "r" (src)                              \
            : "memory");                                    \
    } }                                                             \

#define __RTE_ARM_LOAD_EXC(src, dst, memorder, size) {     \
    RTE_BUILD_BUG_ON(size != 16 && size != 32 &&       \
        size != 64 && size != 128);                \
    if (size == 16)                                    \
        __RTE_ARM_LOAD_EXC_16(src, dst, memorder)  \
    else if (size == 32)                               \
        __RTE_ARM_LOAD_EXC_32(src, dst, memorder)  \
    else if (size == 64)                               \
        __RTE_ARM_LOAD_EXC_64(src, dst, memorder)  \
    else if (size == 128)                              \
        __RTE_ARM_LOAD_EXC_128(src, dst, memorder) \
}

static __pacc_always_inline void
pacc_wait_until_equal_16(volatile uint16_t *addr, uint16_t expected,
        int memorder)
{
    uint16_t value;
    __RTE_ARM_LOAD_EXC_16(addr, value, memorder)
    if (value != expected) {
        __RTE_ARM_SEVL()
        do {
            __RTE_ARM_WFE()
            __RTE_ARM_LOAD_EXC_16(addr, value, memorder)
        } while (value != expected);
    }
}

static __pacc_always_inline void
pacc_wait_until_equal_32(volatile uint32_t *addr, uint32_t expected,
        int memorder)
{
    uint32_t value;
    __RTE_ARM_LOAD_EXC_32(addr, value, memorder)
    if (value != expected) {
        __RTE_ARM_SEVL()
        do {
            __RTE_ARM_WFE()
            __RTE_ARM_LOAD_EXC_32(addr, value, memorder)
        } while (value != expected);
    }
}

static __pacc_always_inline void
pacc_wait_until_equal_64(volatile uint64_t *addr, uint64_t expected,
        int memorder)
{
    uint64_t value;

    __RTE_ARM_LOAD_EXC_64(addr, value, memorder)
    if (value != expected) {
        __RTE_ARM_SEVL()
        do {
            __RTE_ARM_WFE()
            __RTE_ARM_LOAD_EXC_64(addr, value, memorder)
        } while (value != expected);
    }
}

#define RTE_WAIT_UNTIL_MASKED(addr, mask, cond, expected, memorder) do {  \
    const uint32_t size = sizeof(*(addr)) << 3;                       \
    typeof(*(addr)) expected_value = (expected);                      \
    typeof(*(addr)) value;                                            \
    __RTE_ARM_LOAD_EXC((addr), value, memorder, size)                 \
    if (!((value & (mask)) cond expected_value)) {                    \
        __RTE_ARM_SEVL()                                          \
        do {                                                      \
            __RTE_ARM_WFE()                                   \
            __RTE_ARM_LOAD_EXC((addr), value, memorder, size) \
        } while (!((value & (mask)) cond expected_value));        \
    }                                                                 \
} while (0)


//4.prefetch
static __pacc_always_inline void pacc_prefetch0(const volatile void *p)
{
    asm volatile ("PRFM PLDL1KEEP, [%0]" : : "r" (p));
}

static __pacc_always_inline void pacc_prefetch1(const volatile void *p)
{
    asm volatile ("PRFM PLDL2KEEP, [%0]" : : "r" (p));
}

static __pacc_always_inline void pacc_prefetch2(const volatile void *p)
{
    asm volatile ("PRFM PLDL3KEEP, [%0]" : : "r" (p));
}

static __pacc_always_inline void pacc_prefetch_non_temporal(const volatile void *p)
{
    asm volatile ("PRFM PLDL1STRM, [%0]" : : "r" (p));
}

//5.rwlock
/**
 * The pacc_rwlock_t type.
 *
 * cnt is -1 when write lock is held, and > 0 when read locks are held.
 */
typedef struct {
    volatile int32_t cnt; /**< -1 when W lock held, > 0 when R locks held. */
} pacc_rwlock_t;

/**
 * A static rwlock initializer.
 */
#define RTE_RWLOCK_INITIALIZER { 0 }

/**
 * Initialize the rwlock to an unlocked state.
 *
 * @param rwl
 *   A pointer to the rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_init(pacc_rwlock_t *rwl)
{
    rwl->cnt = 0;
}

/**
 * Take a read lock. Loop until the lock is held.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_read_lock(pacc_rwlock_t *rwl)
{
    int32_t x;
    int success = 0;

    while (success == 0) {
        x = __atomic_load_n(&rwl->cnt, __ATOMIC_RELAXED);
        /* write lock is held */
        if (x < 0) {
            pacc_pause();
            continue;
        }
        success = __atomic_compare_exchange_n(&rwl->cnt, &x, x + 1, 1,
                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
    }
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * try to take a read lock.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 * @return
 *   - zero if the lock is successfully taken
 *   - -EBUSY if lock could not be acquired for reading because a
 *     writer holds the lock
 */
static __pacc_always_inline int
pacc_rwlock_read_trylock(pacc_rwlock_t *rwl)
{
    int32_t x;
    int success = 0;

    while (success == 0) {
        x = __atomic_load_n(&rwl->cnt, __ATOMIC_RELAXED);
        /* write lock is held */
        if (x < 0)
            return -EBUSY;
        success = __atomic_compare_exchange_n(&rwl->cnt, &x, x + 1, 1,
                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
    }

    return 0;
}

/**
 * Release a read lock.
 *
 * @param rwl
 *   A pointer to the rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_read_unlock(pacc_rwlock_t *rwl)
{
    __atomic_fetch_sub(&rwl->cnt, 1, __ATOMIC_RELEASE);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * try to take a write lock.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 * @return
 *   - zero if the lock is successfully taken
 *   - -EBUSY if lock could not be acquired for writing because
 *     it was already locked for reading or writing
 */
static __pacc_always_inline int
pacc_rwlock_write_trylock(pacc_rwlock_t *rwl)
{
    int32_t x;

    x = __atomic_load_n(&rwl->cnt, __ATOMIC_RELAXED);
    if (x != 0 || __atomic_compare_exchange_n(&rwl->cnt, &x, -1, 1,
                  __ATOMIC_ACQUIRE, __ATOMIC_RELAXED) == 0)
        return -EBUSY;

    return 0;
}

/**
 * Take a write lock. Loop until the lock is held.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_write_lock(pacc_rwlock_t *rwl)
{
    int32_t x;
    int success = 0;

    while (success == 0) {
        x = __atomic_load_n(&rwl->cnt, __ATOMIC_RELAXED);
        /* a lock is held */
        if (x != 0) {
            pacc_pause();
            continue;
        }
        success = __atomic_compare_exchange_n(&rwl->cnt, &x, -1, 1,
                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
    }
}

/**
 * Release a write lock.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_write_unlock(pacc_rwlock_t *rwl)
{
    __atomic_store_n(&rwl->cnt, 0, __ATOMIC_RELEASE);
}

/**
 * Try to execute critical section in a hardware memory transaction, if it
 * fails or not available take a read lock
 *
 * NOTE: An attempt to perform a HW I/O operation inside a hardware memory
 * transaction always aborts the transaction since the CPU is not able to
 * roll-back should the transaction fail. Therefore, hardware transactional
 * locks are not advised to be used around pacc_eth_rx_burst() and
 * pacc_eth_tx_burst() calls.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_read_lock_tm(pacc_rwlock_t *rwl)
{
    pacc_rwlock_read_lock(rwl);
}


/**
 * Commit hardware memory transaction or release the read lock if the lock is used as a fall-back
 *
 * @param rwl
 *   A pointer to the rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_read_unlock_tm(pacc_rwlock_t *rwl)
{
    pacc_rwlock_read_unlock(rwl);
}


/**
 * Try to execute critical section in a hardware memory transaction, if it
 * fails or not available take a write lock
 *
 * NOTE: An attempt to perform a HW I/O operation inside a hardware memory
 * transaction always aborts the transaction since the CPU is not able to
 * roll-back should the transaction fail. Therefore, hardware transactional
 * locks are not advised to be used around pacc_eth_rx_burst() and
 * pacc_eth_tx_burst() calls.
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_write_lock_tm(pacc_rwlock_t *rwl)
{
    pacc_rwlock_write_lock(rwl);
}

/**
 * Commit hardware memory transaction or release the write lock if the lock is used as a fall-back
 *
 * @param rwl
 *   A pointer to a rwlock structure.
 */
static __pacc_always_inline void
pacc_rwlock_write_unlock_tm(pacc_rwlock_t *rwl)
{
    pacc_rwlock_write_unlock(rwl);
}


//6.spinlock
/**
 * The pacc_spinlock_t type.
 */
typedef struct {
    volatile int locked; /**< lock status 0 = unlocked, 1 = locked */
} pacc_spinlock_t;

/**
 * A static spinlock initializer.
 */
#define RTE_SPINLOCK_INITIALIZER { 0 }

/**
 * Initialize the spinlock to an unlocked state.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static __pacc_always_inline void
pacc_spinlock_init(pacc_spinlock_t *sl)
{
    sl->locked = 0;
}

/**
 * Take the spinlock.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static __pacc_always_inline void
pacc_spinlock_lock(pacc_spinlock_t *sl)
{
    int exp = 0;

    while (!__atomic_compare_exchange_n(&sl->locked, &exp, 1, 0,
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        pacc_wait_until_equal_32((volatile uint32_t *)&sl->locked,
                   0, __ATOMIC_RELAXED);
        exp = 0;
    }
}

/**
 * Release the spinlock.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static __pacc_always_inline void
pacc_spinlock_unlock (pacc_spinlock_t *sl)
{
    __atomic_store_n(&sl->locked, 0, __ATOMIC_RELEASE);
}

/**
 * Try to take the lock.
 *
 * @param sl
 *   A pointer to the spinlock.
 * @return
 *   1 if the lock is successfully taken; 0 otherwise.
 */
 __pacc_warn_unused_result
static __pacc_always_inline int
pacc_spinlock_trylock (pacc_spinlock_t *sl)
{
    int exp = 0;
    return __atomic_compare_exchange_n(&sl->locked, &exp, 1,
                0, /* disallow spurious failure */
                __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

/**
 * Test if the lock is taken.
 *
 * @param sl
 *   A pointer to the spinlock.
 * @return
 *   1 if the lock is currently taken; 0 otherwise.
 */
static __pacc_always_inline int pacc_spinlock_is_locked (pacc_spinlock_t *sl)
{
    return __atomic_load_n(&sl->locked, __ATOMIC_ACQUIRE);
}

/**
 * Test if hardware transactional memory (lock elision) is suppopaccd
 *
 * @return
 *   1 if the hardware transactional memory is suppopaccd; 0 otherwise.
 */
static __pacc_always_inline int pacc_tm_suppopaccd(void)
{
    return 0;
}


/**
 * Try to execute critical section in a hardware memory transaction,
 * if it fails or not available take the spinlock.
 *
 * NOTE: An attempt to perform a HW I/O operation inside a hardware memory
 * transaction always aborts the transaction since the CPU is not able to
 * roll-back should the transaction fail. Therefore, hardware transactional
 * locks are not advised to be used around pacc_eth_rx_burst() and
 * pacc_eth_tx_burst() calls.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static __pacc_always_inline void
pacc_spinlock_lock_tm(pacc_spinlock_t *sl)
{
    pacc_spinlock_lock(sl); /* fall-back */
}

/**
 * Commit hardware memory transaction or release the spinlock if
 * the spinlock is used as a fall-back
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static __pacc_always_inline void
pacc_spinlock_unlock_tm(pacc_spinlock_t *sl)
{
    pacc_spinlock_unlock(sl);
}


/**
 * Try to execute critical section in a hardware memory transaction,
 * if it fails or not available try to take the lock.
 *
 * NOTE: An attempt to perform a HW I/O operation inside a hardware memory
 * transaction always aborts the transaction since the CPU is not able to
 * roll-back should the transaction fail. Therefore, hardware transactional
 * locks are not advised to be used around pacc_eth_rx_burst() and
 * pacc_eth_tx_burst() calls.
 *
 * @param sl
 *   A pointer to the spinlock.
 * @return
 *   1 if the hardware memory transaction is successfully stapaccd
 *   or lock is successfully taken; 0 otherwise.
 */
 __pacc_warn_unused_result
static __pacc_always_inline int
pacc_spinlock_trylock_tm(pacc_spinlock_t *sl)
{
    return pacc_spinlock_trylock(sl);
}


/**
 * The pacc_spinlock_recursive_t type.
 */
typedef struct {
    pacc_spinlock_t sl; /**< the actual spinlock */
    volatile int user; /**< core id using lock, -1 for unused */
    volatile int count; /**< count of time this lock has been called */
} pacc_spinlock_recursive_t;

/**
 * A static recursive spinlock initializer.
 */
#define RTE_SPINLOCK_RECURSIVE_INITIALIZER {RTE_SPINLOCK_INITIALIZER, -1, 0}

/**
 * Initialize the recursive spinlock to an unlocked state.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
static __pacc_always_inline void pacc_spinlock_recursive_init(pacc_spinlock_recursive_t *slr)
{
    pacc_spinlock_init(&slr->sl);
    slr->user = -1;
    slr->count = 0;
}

/**
 * Take the recursive spinlock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
static __pacc_always_inline void pacc_spinlock_recursive_lock(pacc_spinlock_recursive_t *slr)
{
    int id = (int)syscall(SYS_gettid);

    if (slr->user != id) {
        pacc_spinlock_lock(&slr->sl);
        slr->user = id;
    }
    slr->count++;
}
/**
 * Release the recursive spinlock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
static __pacc_always_inline void pacc_spinlock_recursive_unlock(pacc_spinlock_recursive_t *slr)
{
    if (--(slr->count) == 0) {
        slr->user = -1;
        pacc_spinlock_unlock(&slr->sl);
    }

}

/**
 * Try to take the recursive lock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 * @return
 *   1 if the lock is successfully taken; 0 otherwise.
 */
__pacc_warn_unused_result
static __pacc_always_inline int pacc_spinlock_recursive_trylock(pacc_spinlock_recursive_t *slr)
{
    int id = (int)syscall(SYS_gettid);;

    if (slr->user != id) {
        if (pacc_spinlock_trylock(&slr->sl) == 0)
            return 0;
        slr->user = id;
    }
    slr->count++;
    return 1;
}


/**
 * Try to execute critical section in a hardware memory transaction,
 * if it fails or not available take the recursive spinlocks
 *
 * NOTE: An attempt to perform a HW I/O operation inside a hardware memory
 * transaction always aborts the transaction since the CPU is not able to
 * roll-back should the transaction fail. Therefore, hardware transactional
 * locks are not advised to be used around pacc_eth_rx_burst() and
 * pacc_eth_tx_burst() calls.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */

static __pacc_always_inline void
pacc_spinlock_recursive_lock_tm(pacc_spinlock_recursive_t *slr)
{
    pacc_spinlock_recursive_lock(slr); /* fall-back */
}


/**
 * Commit hardware memory transaction or release the recursive spinlock
 * if the recursive spinlock is used as a fall-back
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
static __pacc_always_inline void
pacc_spinlock_recursive_unlock_tm(pacc_spinlock_recursive_t *slr)
{
    pacc_spinlock_recursive_unlock(slr);
}


/**
 * Try to execute critical section in a hardware memory transaction,
 * if it fails or not available try to take the recursive lock
 *
 * NOTE: An attempt to perform a HW I/O operation inside a hardware memory
 * transaction always aborts the transaction since the CPU is not able to
 * roll-back should the transaction fail. Therefore, hardware transactional
 * locks are not advised to be used around pacc_eth_rx_burst() and
 * pacc_eth_tx_burst() calls.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 * @return
 *   1 if the hardware memory transaction is successfully stapaccd
 *   or lock is successfully taken; 0 otherwise.
 */
__pacc_warn_unused_result
static __pacc_always_inline int pacc_spinlock_recursive_trylock_tm(
    pacc_spinlock_recursive_t *slr);

#define RTE_OVERRIDE_IO_H


/**
 * Read a 8-bit value from I/O device memory address *addr*.
 *
 * The relaxed version does not have additional I/O memory barrier, useful in
 * accessing the device registers of integrated controllers which implicitly
 * strongly ordered with respect to memory access.
 *
 * @param addr
 *  I/O memory address to read the value from
 * @return
 *  read value
 */
static __pacc_always_inline uint8_t
pacc_read8_relaxed(const volatile void *addr)
{
    uint8_t val;

    asm volatile(
            "ldrb %w[val], [%x[addr]]"
            : [val] "=r" (val)
            : [addr] "r" (addr));
    return val;
}

/**
 * Read a 16-bit value from I/O device memory address *addr*.
 *
 * The relaxed version does not have additional I/O memory barrier, useful in
 * accessing the device registers of integrated controllers which implicitly
 * strongly ordered with respect to memory access.
 *
 * @param addr
 *  I/O memory address to read the value from
 * @return
 *  read value
 */

static __pacc_always_inline uint16_t
pacc_read16_relaxed(const volatile void *addr)
{
    uint16_t val;

    asm volatile(
            "ldrh %w[val], [%x[addr]]"
            : [val] "=r" (val)
            : [addr] "r" (addr));
    return val;
}
/**
 * Read a 32-bit value from I/O device memory address *addr*.
 *
 * The relaxed version does not have additional I/O memory barrier, useful in
 * accessing the device registers of integrated controllers which implicitly
 * strongly ordered with respect to memory access.
 *
 * @param addr
 *  I/O memory address to read the value from
 * @return
 *  read value
 */

static __pacc_always_inline uint32_t
pacc_read32_relaxed(const volatile void *addr)
{
    uint32_t val;

    asm volatile(
            "ldr %w[val], [%x[addr]]"
            : [val] "=r" (val)
            : [addr] "r" (addr));
    return val;
}
/**
 * Read a 64-bit value from I/O device memory address *addr*.
 *
 * The relaxed version does not have additional I/O memory barrier, useful in
 * accessing the device registers of integrated controllers which implicitly
 * strongly ordered with respect to memory access.
 *
 * @param addr
 *  I/O memory address to read the value from
 * @return
 *  read value
 */

static __pacc_always_inline uint64_t
pacc_read64_relaxed(const volatile void *addr)
{
    uint64_t val;

    asm volatile(
            "ldr %x[val], [%x[addr]]"
            : [val] "=r" (val)
            : [addr] "r" (addr));
    return val;
}
/**
 * Write a 8-bit value to I/O device memory address *addr*.
 *
 * The relaxed version does not have additional I/O memory barrier, useful in
 * accessing the device registers of integrated controllers which implicitly
 * strongly ordered with respect to memory access.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */

static __pacc_always_inline void
pacc_write8_relaxed(uint8_t val, volatile void *addr)
{
    asm volatile(
            "strb %w[val], [%x[addr]]"
            :
            : [val] "r" (val), [addr] "r" (addr));
}

/**
 * Write a 16-bit value to I/O device memory address *addr*.
 *
 * The relaxed version does not have additional I/O memory barrier, useful in
 * accessing the device registers of integrated controllers which implicitly
 * strongly ordered with respect to memory access.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */

static __pacc_always_inline void
pacc_write16_relaxed(uint16_t val, volatile void *addr)
{
    asm volatile(
            "strh %w[val], [%x[addr]]"
            :
            : [val] "r" (val), [addr] "r" (addr));
}
/**
 * Write a 32-bit value to I/O device memory address *addr*.
 *
 * The relaxed version does not have additional I/O memory barrier, useful in
 * accessing the device registers of integrated controllers which implicitly
 * strongly ordered with respect to memory access.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */

static __pacc_always_inline void
pacc_write32_relaxed(uint32_t val, volatile void *addr)
{
    asm volatile(
            "str %w[val], [%x[addr]]"
            :
            : [val] "r" (val), [addr] "r" (addr));
}
/**
 * Write a 64-bit value to I/O device memory address *addr*.
 *
 * The relaxed version does not have additional I/O memory barrier, useful in
 * accessing the device registers of integrated controllers which implicitly
 * strongly ordered with respect to memory access.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */

static __pacc_always_inline void
pacc_write64_relaxed(uint64_t val, volatile void *addr)
{
    asm volatile(
            "str %x[val], [%x[addr]]"
            :
            : [val] "r" (val), [addr] "r" (addr));
}
/**
 * Read a 8-bit value from I/O device memory address *addr*.
 *
 * @param addr
 *  I/O memory address to read the value from
 * @return
 *  read value
 */

static __pacc_always_inline uint8_t
pacc_read8(const volatile void *addr)
{
    uint8_t val;
    val = pacc_read8_relaxed(addr);
    pacc_io_rmb();
    return val;
}
/**
 * Read a 16-bit value from I/O device memory address *addr*.
 *
 *
 * @param addr
 *  I/O memory address to read the value from
 * @return
 *  read value
 */

static __pacc_always_inline uint16_t
pacc_read16(const volatile void *addr)
{
    uint16_t val;
    val = pacc_read16_relaxed(addr);
    pacc_io_rmb();
    return val;
}
/**
 * Read a 32-bit value from I/O device memory address *addr*.
 *
 * @param addr
 *  I/O memory address to read the value from
 * @return
 *  read value
 */

static __pacc_always_inline uint32_t
pacc_read32(const volatile void *addr)
{
    uint32_t val;
    val = pacc_read32_relaxed(addr);
    pacc_io_rmb();
    return val;
}
/**
 * Read a 64-bit value from I/O device memory address *addr*.
 *
 * @param addr
 *  I/O memory address to read the value from
 * @return
 *  read value
 */

static __pacc_always_inline uint64_t
pacc_read64(const volatile void *addr)
{
    uint64_t val;
    val = pacc_read64_relaxed(addr);
    pacc_io_rmb();
    return val;
}

/**
 * Write a 8-bit value to I/O device memory address *addr*.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */

static __pacc_always_inline void
pacc_write8(uint8_t value, volatile void *addr)
{
    pacc_io_wmb();
    pacc_write8_relaxed(value, addr);
}
/**
 * Write a 16-bit value to I/O device memory address *addr*.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */

static __pacc_always_inline void
pacc_write16(uint16_t value, volatile void *addr)
{
    pacc_io_wmb();
    pacc_write16_relaxed(value, addr);
}

/**
 * Write a 32-bit value to I/O device memory address *addr*.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */

static __pacc_always_inline void
pacc_write32(uint32_t value, volatile void *addr)
{
    pacc_io_wmb();
    pacc_write32_relaxed(value, addr);
}

/**
 * Write a 64-bit value to I/O device memory address *addr*.
 *
 * @param value
 *  Value to write
 * @param addr
 *  I/O memory address to write the value to
 */






#endif
