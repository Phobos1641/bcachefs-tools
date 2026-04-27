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

#define bch2_shrinker_get_private(_s)           ((_s)->private_data)
#define bch2_shrinker_set_private(_s, _priv)    ((_s)->private_data) = _priv;

static inline void bch2_ratelimit_atomic_reset(struct ratelimit_state *rs)
{
    atomic_set(&rs->rs_n_left, 0);
    atomic_set(&rs->missed,    0);
}

#else

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

#endif /* __KERNEL__ */

#endif /* _BCACHEFS_GLUE_H */
