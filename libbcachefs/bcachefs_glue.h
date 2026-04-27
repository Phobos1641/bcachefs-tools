#ifndef _BCACHEFS_GLUE_H
#define _BCACHEFS_GLUE_H

#include <linux/version.h>
#include <linux/compiler.h>
#include <linux/ratelimit.h>

#ifndef __counted_by
	#define __counted_by(nr)
#endif

#ifndef TYPEOF_UNQUAL
	#define TYPEOF_UNQUAL(exp) __typeof_unqual__(exp)
#endif

#ifndef __KERNEL__

#define __bch2_bin_attribute_const const

#define bch2_shrinker_get_private(_s)           ((_s)->private_data)
#define bch2_shrinker_set_private(_s, _priv)    ((_s)->private_data) = _priv;

static inline void bch2_ratelimit_atomic_reset(struct ratelimit_state *rs)
{
    atomic_set(&rs->rs_n_left, 0);
    atomic_set(&rs->missed,    0);
}

#define bch2_chacha_init(_state, _key, _iv)				chacha_init(_state, _key, _iv)
#define bch2_chacha20_crypt(_state, _dst, _src, _bytes)	chacha20_crypt(_state, _dst, _src, _bytes)
#define bch2_chacha_zeroize_state(_state)				chacha_zeroize_state(_state)

#define bch2_bio_add_virt_nofail(_bio, _vaddr, _len) \
	bio_add_virt_nofail(_bio, _vaddr, _len)

#else

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)
#define MAX_PAGE_ORDER MAX_ORDER
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
#define __bch2_bin_attribute_const
#else
#define __bch2_bin_attribute_const	const
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
#define FILEID_BCACHEFS_WITH_PARENT 0xb2
#define FILEID_BCACHEFS_WITHOUT_PARENT 0xb1
#endif

#ifndef BCACHEFS_SUPER_MAGIC
#define BCACHEFS_SUPER_MAGIC	0xca451a4e
#endif

#ifndef struct_size_t
#define struct_size_t(type, member, count)                                     \
       struct_size((type *)NULL, member, count)
#endif

#ifndef cmp_int
#define cmp_int(l ,r) (((l) > (r)) - ((l) < (r)))
#endif

#ifndef alloc_hooks
#define alloc_hooks(expr) (expr)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
static inline unsigned memalloc_flags_save(unsigned flags)
{
	unsigned oldflags = ~current->flags & flags;
	current->flags |= flags;
	return oldflags;
}

static inline void memalloc_flags_restore(unsigned flags)
{
	current->flags &= ~flags;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,13,0)
#define __DEFINE_CLASS_IS_CONDITIONAL(_name, _is_cond)	\
static __maybe_unused const bool class_##_name##_is_conditional = _is_cond

#define DEFINE_CLASS_IS_UNCONDITIONAL(_name)		\
	__DEFINE_CLASS_IS_CONDITIONAL(_name, false);	\
	static inline void * class_##_name##_lock_ptr(class_##_name##_t *_T) \
	{ return (void *)1; }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#define sort_nonatomic(base, num, size, cmp, swap)  \
    sort(base, num, size, cmp, swap)

#define sort_r_nonatomic(base, num, size, cmp, swap, priv)  \
    sort_r(base, num, size, cmp, swap, priv)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
DEFINE_FREE(kvfree, void *, if (_T) kvfree(_T))
#endif

#ifndef __DEFINE_LOCK_GUARD_1
#define __DEFINE_LOCK_GUARD_1(_name, _type, ...)			\
static __always_inline class_##_name##_t class_##_name##_constructor(_type *l) \
	__no_context_analysis						\
{									\
	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
	__VA_ARGS__;							\
	return _t;							\
}
#endif

#ifndef __DEFINE_LOCK_GUARD_0
#define __DEFINE_LOCK_GUARD_0(_name, ...)				\
static __always_inline class_##_name##_t class_##_name##_constructor(void) \
	__no_context_analysis						\
{									\
	class_##_name##_t _t = { .lock = (void*)1 },			\
			 *_T __maybe_unused = &_t;			\
	__VA_ARGS__;							\
	return _t;							\
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
DEFINE_LOCK_GUARD_1(percpu_read, struct percpu_rw_semaphore,
                    percpu_down_read(_T->lock),
                    percpu_up_read(_T->lock))

DEFINE_LOCK_GUARD_1(percpu_write, struct percpu_rw_semaphore,
                    percpu_down_read(_T->lock),
                    percpu_up_read(_T->lock))
#endif

#ifndef this_cpu_try_cmpxchg
#define this_cpu_try_cmpxchg(pcp, oldp, new)            \
({                                                      \
    typeof(*(oldp)) __old = *(oldp);                    \
    typeof(*(oldp)) __prev = this_cpu_cmpxchg(pcp, __old, new); \
    bool __success = (__prev == __old);                 \
    if (!__success)                                     \
        *(oldp) = __prev;                               \
    __success;                                          \
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
static inline void mm_account_reclaimed_pages(unsigned long pages)
{
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += pages;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
struct bch_shrinker_wrap {
	struct shrinker sh;		/* kernel's real shrinker -- this *must* be first */
	char name[64];
	void *private_data;		/* the new field that doesn't exist in the kernel's struct */
};

static inline struct shrinker *shrinker_alloc(unsigned int flags, const char *fmt, ...)
{
	struct bch_shrinker_wrap *w = kzalloc(sizeof(*w), GFP_KERNEL);
	va_list args;
	if (!w)
		return NULL;
	va_start(args, fmt);
	vsnprintf(w->name, sizeof(w->name), fmt, args);
	va_end(args);
	return &w->sh;  /* caller sees a shrinker structure, as expected */
}

#define bch2_shrinker_get_private(_s) \
    (container_of((_s), struct bch_shrinker_wrap, sh)->private_data)

static inline void bch2_shrinker_set_private(struct shrinker *_s, void *priv)
{
    container_of(_s, struct bch_shrinker_wrap, sh)->private_data = priv;
}
#else
#define bch2_shrinker_get_private(_s) \
	((_s)->private_data)

static inline void bch2_shrinker_set_private(struct shrinker *_s, void *priv)
{
    _s->private_data = priv;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
static inline void bch2_ratelimit_atomic_reset(struct ratelimit_state *rs)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&rs->lock, flags);
	rs->printed = 0;
	rs->missed  = 0;
	rs->begin   = jiffies;
	raw_spin_unlock_irqrestore(&rs->lock, flags);
}
#else
static inline void bch2_ratelimit_atomic_reset(struct ratelimit_state *rs)
{
	atomic_set(&rs->rs_n_left, 0);
	atomic_set(&rs->missed,    0);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
struct chacha_state {
	u32 x[16];
};

static inline void bch2_chacha_init(struct chacha_state *state,
                                    const u32 *key, const u8 *iv)
{
	chacha_init(state->x, key, iv);
}

static inline void bch2_chacha20_crypt(struct chacha_state *state,
			u8 *dst, const u8 *src,
			unsigned int bytes)
{
	chacha20_crypt(state->x, dst, src, bytes);
}

static inline void bch2_chacha_zeroize_state(struct chacha_state *state)
{
	memzero_explicit(state->x, sizeof(state->x));
}
#else
static inline void bch2_chacha_init(struct chacha_state *state,
			const u32 *key, const u8 *iv)
{
	chacha_init(state, key, iv);
}

static inline void bch2_chacha20_crypt(struct chacha_state *state,
			u8 *dst, const u8 *src,
			unsigned int bytes)
{
	chacha20_crypt(state, dst, src, bytes);
}

static inline void bch2_chacha_zeroize_state(struct chacha_state *state)
{
	chacha_zeroize_state(state);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
static inline void bch2_bio_add_virt_nofail(struct bio *bio, void *vaddr, unsigned len)
{
	__bio_add_page(bio, virt_to_page(vaddr), len, offset_in_page(vaddr));
}
#else
#define bch2_bio_add_virt_nofail(_bio, _vaddr, _len) \
	bio_add_virt_nofail(_bio, _vaddr, _len)
#endif

#endif /* __KERNEL__ */

#endif /* _BCACHEFS_GLUE_H */
