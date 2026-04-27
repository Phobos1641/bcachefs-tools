#ifndef _BCACHEFS_GLUE_H
#define _BCACHEFS_GLUE_H

#include <linux/compiler.h>

#ifndef __counted_by
	#define __counted_by(nr)
#endif

#ifndef TYPEOF_UNQUAL
	#define TYPEOF_UNQUAL(exp) __typeof_unqual__(exp)
#endif

#endif /* _BCACHEFS_GLUE_H */
