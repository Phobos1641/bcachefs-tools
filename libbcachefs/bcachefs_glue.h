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

#ifndef __force
#define __force
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0)
#define __bch2_assign_str(dst)                                               \
    do {                                                                \
        char *__str__ = __get_str(dst);                                 \
        int __len__ = __get_dynamic_array_len(dst) - 1;                 \
        WARN_ON_ONCE(!(dst));                                           \
        memcpy(__str__, (dst) ? (const char *)(dst) : "(null)", __len__);\
        __str__[__len__] = '\0';                                        \
    } while (0)
#else
#define __bch2_assign_str(dst) \
	__assign_str(dst)
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

#define bch_idmap mnt_idmap

#define bch2_kvrealloc(p, oldsize, newsize, flags) \
	kvrealloc((p), (newsize), (flags))

#define bch_file file

#define bch2_bdev_from_handle(_handle) \
	file_bdev(_handle)

#define bch2_bdev_file_open_by_path(_path, _mode, _holder, _hops) \
	bdev_file_open_by_path(_path, _mode, _holder, _hops)

#define bch2_bdev_release(_fp) \
	bdev_fput((_fp))

#else

#include <linux/cleanup.h>
#include <linux/generic-radix-tree.h>
#include <linux/percpu-defs.h>
#include <linux/percpu-rwsem.h>
#include <linux/rcupdate.h>
#include <linux/shrinker.h>
#include <linux/sort.h>
#include <linux/swap.h>
#include <linux/ratelimit.h>
#include <linux/bio.h>
#include <linux/string.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/fs_parser.h>
#include <crypto/chacha.h>

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

#ifndef BLK_STS_RESV_CONFLICT
#define BLK_STS_RESV_CONFLICT   ((__force blk_status_t)6)
#endif

#ifndef BLK_STS_DURATION_LIMIT
#define BLK_STS_DURATION_LIMIT  ((__force blk_status_t)17)
#endif

#ifndef BLK_STS_INVAL
#define BLK_STS_INVAL           ((__force blk_status_t)19)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
static inline const char *blk_status_to_str(blk_status_t status)
{
    static const struct {
        int errno;
        const char *name;
    } bch2_blk_errors[] = {
	[BLK_STS_OK]		= { 0,		"" },
	[BLK_STS_NOTSUPP]	= { -EOPNOTSUPP, "operation not supported" },
	[BLK_STS_TIMEOUT]	= { -ETIMEDOUT,	"timeout" },
	[BLK_STS_NOSPC]		= { -ENOSPC,	"critical space allocation" },
	[BLK_STS_TRANSPORT]	= { -ENOLINK,	"recoverable transport" },
	[BLK_STS_TARGET]	= { -EREMOTEIO,	"critical target" },
	[BLK_STS_RESV_CONFLICT]	= { -EBADE,	"reservation conflict" },
	[BLK_STS_MEDIUM]	= { -ENODATA,	"critical medium" },
	[BLK_STS_PROTECTION]	= { -EILSEQ,	"protection" },
	[BLK_STS_RESOURCE]	= { -ENOMEM,	"kernel resource" },
	[BLK_STS_DEV_RESOURCE]	= { -EBUSY,	"device resource" },
	[BLK_STS_AGAIN]		= { -EAGAIN,	"nonblocking retry" },
	[BLK_STS_OFFLINE]	= { -ENODEV,	"device offline" },

	/* device mapper special case, should not leak out: */
	[BLK_STS_DM_REQUEUE]	= { -EREMCHG, "dm internal retry" },

	/* zone device specific errors */
	[BLK_STS_ZONE_OPEN_RESOURCE]	= { -ETOOMANYREFS, "open zones exceeded" },
	[BLK_STS_ZONE_ACTIVE_RESOURCE]	= { -EOVERFLOW, "active zones exceeded" },

	/* Command duration limit device-side timeout */
	[BLK_STS_DURATION_LIMIT]	= { -ETIME, "duration limit exceeded" },

	[BLK_STS_INVAL]		= { -EINVAL,	"invalid" },

	/* everything else not covered above: */
	[BLK_STS_IOERR]		= { -EIO,	"I/O" },
    };
    unsigned int idx = (unsigned int)status;
    if (idx >= ARRAY_SIZE(bch2_blk_errors) || !bch2_blk_errors[idx].name)
        return "<null>";
    return bch2_blk_errors[idx].name;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
static inline unsigned int bio_add_vmalloc_chunk(struct bio *bio, void *vaddr, unsigned len)
{
	unsigned int offset = offset_in_page(vaddr);

	len = min(len, PAGE_SIZE - offset);
	if (bio_add_page(bio, vmalloc_to_page(vaddr), len, offset) < len)
		return 0;
	if (op_is_write(bio_op(bio)))
		flush_kernel_vmap_range(vaddr, len);
	return len;
}

static inline bool bio_add_vmalloc(struct bio *bio, void *vaddr, unsigned int len)
{
	do {
		unsigned int added = bio_add_vmalloc_chunk(bio, vaddr, len);

		if (!added)
			return false;
		vaddr += added;
		len -= added;
	} while (len);

	return true;
}
#endif

#ifndef QSTR_INIT
#define QSTR_INIT(n,l) { { { .len = l } }, .name = n }
#endif

#ifndef QSTR
#define QSTR(n) (struct qstr)QSTR_INIT(n, strlen(n))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
static const struct constant_table bool_names[] = {
	{ "0",		false },
	{ "1",		true },
	{ "false",	false },
	{ "no",		false },
	{ "true",	true },
	{ "yes",	true },
	{ },
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
static inline int ida_find_first_range(struct ida *ida, unsigned int min, unsigned int max)
{
	unsigned long index = min / IDA_BITMAP_BITS;
	unsigned int offset = min % IDA_BITMAP_BITS;
	unsigned long *addr, size, bit;
	unsigned long tmp = 0;
	unsigned long flags;
	void *entry;
	int ret;

	if ((int)min < 0)
		return -EINVAL;
	if ((int)max < 0)
		max = INT_MAX;

	xa_lock_irqsave(&ida->xa, flags);

	entry = xa_find(&ida->xa, &index, max / IDA_BITMAP_BITS, XA_PRESENT);
	if (!entry) {
		ret = -ENOENT;
		goto err_unlock;
	}

	if (index > min / IDA_BITMAP_BITS)
		offset = 0;
	if (index * IDA_BITMAP_BITS + offset > max) {
		ret = -ENOENT;
		goto err_unlock;
	}

	if (xa_is_value(entry)) {
		tmp = xa_to_value(entry);
		addr = &tmp;
		size = BITS_PER_XA_VALUE;
	} else {
		addr = ((struct ida_bitmap *)entry)->bitmap;
		size = IDA_BITMAP_BITS;
	}

	bit = find_next_bit(addr, size, offset);

	xa_unlock_irqrestore(&ida->xa, flags);

	if (bit == size ||
	    index * IDA_BITMAP_BITS + bit > max)
		return -ENOENT;

	return index * IDA_BITMAP_BITS + bit;

err_unlock:
	xa_unlock_irqrestore(&ida->xa, flags);
	return ret;
}

static inline int ida_find_first(struct ida *ida)
{
	return ida_find_first_range(ida, 0, ~0);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#define FS_LBS 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)
#define GENRADIX_NODE_SHIFT	9
#define GENRADIX_NODE_SIZE	(1U << GENRADIX_NODE_SHIFT)

#define GENRADIX_ARY		(GENRADIX_NODE_SIZE / sizeof(struct genradix_node *))
#define GENRADIX_ARY_SHIFT	ilog2(GENRADIX_ARY)

struct genradix_node {
	union {
		/* Interior node: */
		struct genradix_node	*children[GENRADIX_ARY];

		/* Leaf: */
		u8			data[GENRADIX_NODE_SIZE];
	};
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
#define GENRADIX_MAX_DEPTH	\
	DIV_ROUND_UP(BITS_PER_LONG - GENRADIX_NODE_SHIFT, GENRADIX_ARY_SHIFT)

#define GENRADIX_DEPTH_MASK				\
	((unsigned long) (roundup_pow_of_two(GENRADIX_MAX_DEPTH + 1) - 1))

#define __genradix_objs_per_page(_radix)			\
	(GENRADIX_NODE_SIZE / sizeof((_radix)->type[0]))

static inline struct genradix_node *genradix_root_to_node(struct genradix_root *r)
{
	return (void *) ((unsigned long) r & ~GENRADIX_DEPTH_MASK);
}

static inline int genradix_depth_shift(unsigned depth)
{
	return GENRADIX_NODE_SHIFT + GENRADIX_ARY_SHIFT * depth;
}

static inline size_t genradix_depth_size(unsigned depth)
{
	return 1UL << genradix_depth_shift(depth);
}

static inline unsigned genradix_root_to_depth(struct genradix_root *r)
{
	return (unsigned long) r & GENRADIX_DEPTH_MASK;
}

static inline void *__genradix_iter_peek_prev(struct genradix_iter *iter,
				struct __genradix *radix,
				size_t objs_per_page,
				size_t obj_size_plus_page_remainder)
{
	struct genradix_root *r;
	struct genradix_node *n;
	unsigned level, i;

	if (iter->offset == SIZE_MAX)
		return NULL;

restart:
	r = READ_ONCE(radix->root);
	if (!r)
		return NULL;

	n	= genradix_root_to_node(r);
	level	= genradix_root_to_depth(r);

	if (ilog2(iter->offset) >= genradix_depth_shift(level)) {
		iter->offset = genradix_depth_size(level);
		iter->pos = (iter->offset >> GENRADIX_NODE_SHIFT) * objs_per_page;

		iter->offset -= obj_size_plus_page_remainder;
		iter->pos--;
	}

	while (level) {
		level--;

		i = (iter->offset >> genradix_depth_shift(level)) &
			(GENRADIX_ARY - 1);

		while (!n->children[i]) {
			size_t objs_per_ptr = genradix_depth_size(level);

			iter->offset = round_down(iter->offset, objs_per_ptr);
			iter->pos = (iter->offset >> GENRADIX_NODE_SHIFT) * objs_per_page;

			if (!iter->offset)
				return NULL;

			iter->offset -= obj_size_plus_page_remainder;
			iter->pos--;

			if (!i)
				goto restart;
			--i;
		}

		n = n->children[i];
	}

	return &n->data[iter->offset & (GENRADIX_NODE_SIZE - 1)];
}

#define __genradix_page_remainder(_radix)			\
	(GENRADIX_NODE_SIZE % sizeof((_radix)->type[0]))

#define genradix_iter_peek_prev(_iter, _radix)			\
	(__genradix_cast(_radix)				\
	 __genradix_iter_peek_prev(_iter, &(_radix)->tree,	\
			__genradix_objs_per_page(_radix),	\
			__genradix_obj_size(_radix) +		\
			__genradix_page_remainder(_radix)))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)
static inline void __genradix_iter_rewind(struct genradix_iter *iter,
					  size_t obj_size)
{
	if (iter->offset == 0 ||
	    iter->offset == SIZE_MAX) {
		iter->offset = SIZE_MAX;
		return;
	}

	if ((iter->offset & (GENRADIX_NODE_SIZE - 1)) == 0)
		iter->offset -= GENRADIX_NODE_SIZE % obj_size;

	iter->offset -= obj_size;
	iter->pos--;
}

#define genradix_iter_rewind(_iter, _radix)			\
	__genradix_iter_rewind(_iter, __genradix_obj_size(_radix))

#define genradix_last_pos(_radix)				\
	(SIZE_MAX / GENRADIX_NODE_SIZE * __genradix_objs_per_page(_radix) - 1)

#define genradix_for_each_reverse(_radix, _iter, _p)		\
	for (_iter = genradix_iter_init(_radix,	genradix_last_pos(_radix));\
	     (_p = genradix_iter_peek_prev(&_iter, _radix)) != NULL;\
	     genradix_iter_rewind(&_iter, _radix))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
struct bdev_inode {
	struct block_device bdev;
	struct inode vfs_inode;
};

static  __cacheline_aligned_in_smp DEFINE_MUTEX(bdev_lock);

static inline struct bdev_inode *BDEV_I(struct inode *inode)
{
	return container_of(inode, struct bdev_inode, vfs_inode);
}

static inline struct inode *BD_INODE(struct block_device *bdev)
{
	return &container_of(bdev, struct bdev_inode, bdev)->vfs_inode;
}

static inline struct block_device *file_bdev(struct file *bdev_file)
{
	return I_BDEV(bdev_file->f_mapping->host);
}

static inline bool bdev_unclaimed(const struct file *bdev_file)
{
	return bdev_file->private_data == BDEV_I(bdev_file->f_mapping->host);
}

#ifndef BD_WRITE_HOLDER
#define bch2_bdev_test_flag_holder(_bdev) ((_bdev)->bd_write_holder == true)
#define bch2_bdev_set_flag_holder(_bdev) ((_bdev)->bd_write_holder = true)
#define bch2_bdev_clear_flag_holder(_bdev) ((_bdev)->bd_write_holder = false)
#else
#define bch2_bdev_test_flag_holder(_bdev) bdev_test_flag((_bdev), BD_WRITE_HOLDER)
#define bch2_bdev_set_flag_holder(_bdev) bdev_set_flag((_bdev), BD_WRITE_HOLDER)
#define bch2_bdev_clear_flag_holder(_bdev) bdev_clear_flag((_bdev), BD_WRITE_HOLDER)
#endif

#if 0
static void __disk_unblock_events(struct gendisk *disk, bool check_now)
{
	struct disk_events *ev = disk->ev;
	unsigned long intv;
	unsigned long flags;

	spin_lock_irqsave(&ev->lock, flags);

	if (WARN_ON_ONCE(ev->block <= 0))
		goto out_unlock;

	if (--ev->block)
		goto out_unlock;

	intv = disk_events_poll_jiffies(disk);
	if (check_now)
		queue_delayed_work(system_freezable_power_efficient_wq,
				&ev->dwork, 0);
	else if (intv)
		queue_delayed_work(system_freezable_power_efficient_wq,
				&ev->dwork, intv);
out_unlock:
	spin_unlock_irqrestore(&ev->lock, flags);
}

void disk_unblock_events(struct gendisk *disk)
{
	if (disk->ev)
		__disk_unblock_events(disk, false);
}
#endif

extern void disk_unblock_events(struct gendisk *disk);

static void bd_end_claim(struct block_device *bdev, void *holder)
{
	struct block_device *whole = bdev_whole(bdev);
	bool unblock = false;

	/*
	 * Release a claim on the device.  The holder fields are protected with
	 * bdev_lock.  open_mutex is used to synchronize disk_holder unlinking.
	 */
	mutex_lock(&bdev_lock);
	WARN_ON_ONCE(bdev->bd_holder != holder);
	WARN_ON_ONCE(--bdev->bd_holders < 0);
	WARN_ON_ONCE(--whole->bd_holders < 0);
	if (!bdev->bd_holders) {
		mutex_lock(&bdev->bd_holder_lock);
		bdev->bd_holder = NULL;
		bdev->bd_holder_ops = NULL;
		mutex_unlock(&bdev->bd_holder_lock);
		if (bch2_bdev_test_flag_holder(bdev))
			unblock = true;
	}
	if (!whole->bd_holders)
		whole->bd_holder = NULL;
	mutex_unlock(&bdev_lock);

	/*
	 * If this was the last claim, remove holder link and unblock evpoll if
	 * it was a write holder.
	 */
	if (unblock) {
		disk_unblock_events(bdev->bd_disk);
		bch2_bdev_clear_flag_holder(bdev);
	}
}

static inline void bd_yield_claim(struct file *bdev_file)
{
	struct block_device *bdev = file_bdev(bdev_file);
	void *holder = bdev_file->private_data;

	lockdep_assert_held(&bdev->bd_disk->open_mutex);

	if (WARN_ON_ONCE(IS_ERR_OR_NULL(holder)))
		return;

	if (!bdev_unclaimed(bdev_file))
		bd_end_claim(bdev, holder);
}

static inline void bdev_fput(struct file *bdev_file)
{
	if (WARN_ON_ONCE(bdev_file->f_op != &def_blk_fops))
		return;

	if (bdev_file->private_data) {
		struct block_device *bdev = file_bdev(bdev_file);
		struct gendisk *disk = bdev->bd_disk;

		mutex_lock(&disk->open_mutex);
		bd_yield_claim(bdev_file);
		/*
		 * Tell release we already gave up our hold on the
		 * device and if write restrictions are available that
		 * we already gave up write access to the device.
		 */
		bdev_file->private_data = BDEV_I(bdev_file->f_mapping->host);
		mutex_unlock(&disk->open_mutex);
	}

	fput(bdev_file);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
#define bch_idmap user_namespace

#define file_mnt_idmap(_fp) \
	file_mnt_user_ns(_fp)
#else
#define bch_idmap mnt_idmap
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline void* bch2_kvrealloc(void *p, size_t oldsize, size_t newsize, int flags)
{
	void *ret = kvrealloc(p, oldsize, newsize, flags);

	if (ret && newsize > oldsize)
		memset((u8 *)ret + oldsize, 0, newsize - oldsize);

	return ret;
}
#else
#define bch2_kvrealloc(p, oldsize, newsize, flags) \
	kvrealloc((p), (newsize), (flags))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
#define BCH_BLK_OPEN_READ	BLK_OPEN_READ
#define BCH_BLK_OPEN_WRITE	BLK_OPEN_WRITE
#define BCH_BLK_OPEN_EXCL	BLK_OPEN_EXCL

#define bch_blk_mode_t fmode_t

#define bch_file bch_file_handle
#else
#define BCH_BLK_OPEN_READ	FMODE_READ
#define BCH_BLK_OPEN_WRITE	FMODE_WRITE
#define BCH_BLK_OPEN_EXCL	FMODE_EXCL

#define bch_blk_mode_t blk_mode_t

#define bch_file file
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
struct bch_file_handle {
	struct block_device *bdev;
	void *holder;
	fmode_t mode;
};

static inline struct block_device *bch2_bdev_from_handle(struct bch_file_handle *h)
{
	return h->bdev;
}

#define bch2_bdev_set_file(_file_handle, _fp) \
	((_file_handle)->bdev = _fp)

static inline struct bch_file * bch2_bdev_file_open_by_path(const char *path, bch_blk_mode_t mode, void *holder, const struct blk_holder_ops *hops)
{
	struct bch_file_handle *h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return ERR_PTR(-ENOMEM);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	h->bdev = blkdev_get_by_path(path, mode, holder);
#else
	h->bdev = blkdev_get_by_path(path, mode, holder, hops);
#endif
	if (IS_ERR(h->bdev)) {
		long err = PTR_ERR(h->bdev);
		kfree(h);
		return ERR_PTR(err);
	}
	h->holder = holder;
	h->mode = mode;
	return h;
}

static inline void bch2_bdev_release(struct bch_file_handle *h)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
	blkdev_put(h->bdev, h->mode);
#else
	blkdev_put(h->bdev, h->holder);
#endif
	kfree(h);
}
#else
#define bch2_bdev_from_handle(_handle) \
	file_bdev(_handle)

#define bch2_bdev_file_open_by_path(_path, _mode, _holder, _hops) \
	bdev_file_open_by_path(_path, _mode, _holder, _hops)

#define bch2_bdev_release(_fp) \
	bdev_fput((_fp))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)
#define bdev_freeze freeze_bdev
#define bdev_thaw thaw_bdev
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline void mapping_set_folio_min_order(struct address_space *mapping, unsigned int min_order)
{
}

static inline unsigned int mapping_min_folio_order(const struct address_space *mapping)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
static inline void d_mark_tmpfile(struct file *file, struct inode *inode)
{
	struct dentry *dentry = file->f_path.dentry;

	BUG_ON(dentry->d_name.name != dentry->d_iname ||
		!hlist_unhashed(&dentry->d_u.d_alias) ||
		!d_unlinked(dentry));
	spin_lock(&dentry->d_parent->d_lock);
	spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
	dentry->d_name.len = sprintf(dentry->d_iname, "#%llu",
				(unsigned long long)inode->i_ino);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dentry->d_parent->d_lock);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline void unpin_user_folio(struct folio *folio, unsigned long npages)
{
	unsigned long i;
	for (i = 0; i < npages; ++i)
		unpin_user_page(folio_page(folio, i));
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#define inode_state_wait_address(inode, bit) \
	((char *)&(inode)->i_state + (bit))

static inline struct wait_queue_head *inode_bit_waitqueue(struct wait_bit_queue_entry *wqe,
			struct inode *inode, u32 bit)
{
	void *bit_address;

	bit_address = inode_state_wait_address(inode, bit);
	init_wait_var_entry(wqe, bit_address, 0);
	return __var_waitqueue(bit_address);
}

static inline void inode_wake_up_bit(struct inode *inode, u32 bit)
{
	/* Caller is responsible for correct memory barriers. */
	wake_up_var(inode_state_wait_address(inode, bit));
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
static inline int inode_init_always_gfp(struct super_block *sb,
			struct inode *inode, gfp_t gfp)
{
	if (gfp & __GFP_DIRECT_RECLAIM)
		return inode_init_always(sb, inode);

	int ret;

	unsigned int noio_flags = memalloc_noio_save();
	ret = inode_init_always(sb, inode);
	memalloc_noio_restore(noio_flags);

	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
static inline bool in_group_or_capable(struct bch_idmap *idmap,
			const struct inode *inode, vfsgid_t vfsgid)
{
	if (vfsgid_in_group_p(vfsgid))
		return true;
	if (capable_wrt_inode_uidgid(idmap, inode, CAP_FSETID))
		return true;
	return false;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
extern bool in_group_or_capable(struct user_namespace *mnt_userns,
			const struct inode *inode, vfsgid_t vfsgid);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
static inline void folio_end_read(struct folio *folio, bool success)
{
	if (likely(success))
		folio_mark_uptodate(folio);
	folio_unlock(folio);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 10)
static inline struct timespec64 inode_get_atime(const struct inode *inode)
{
	return inode->i_atime;
}

static inline struct timespec64 inode_get_mtime(const struct inode *inode)
{
	return inode->i_mtime;
}

static inline struct timespec64 inode_get_ctime(const struct inode *inode)
{
	return inode->i_ctime;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
static inline vfsuid_t i_uid_into_vfsuid(struct user_namespace *mnt_userns,
			const struct inode *inode)
{
	return VFSUIDT_INIT(i_uid_into_mnt(mnt_userns, inode));
}

static inline vfsgid_t i_gid_into_vfsgid(struct user_namespace *mnt_userns,
			const struct inode *inode)
{
	return VFSGIDT_INIT(i_gid_into_mnt(mnt_userns, inode));
}
#endif

#endif /* __KERNEL__ */

#endif /* _BCACHEFS_GLUE_H */
