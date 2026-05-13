/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_FSCRYPT_H
#define BTRFS_FSCRYPT_H

#include <linux/fscrypt.h>
#include "extent_map.h"

#include "fs.h"

#ifdef CONFIG_FS_ENCRYPTION
int btrfs_fscrypt_get_disk_name(struct extent_buffer *leaf,
				struct btrfs_dir_item *di,
				struct fscrypt_str *qstr);

bool btrfs_fscrypt_match_name(struct fscrypt_name *fname,
			      struct extent_buffer *leaf,
			      unsigned long de_name, u32 de_name_len);
int btrfs_fscrypt_load_extent_info(struct btrfs_inode *inode,
				   struct btrfs_path *path,
				   struct btrfs_key *key,
				   struct extent_map *em);
void btrfs_fscrypt_save_extent_info(struct btrfs_path *path, u8 *ctx, unsigned long size);
ssize_t btrfs_fscrypt_context_for_new_extent(struct btrfs_inode *inode,
					     struct fscrypt_extent_info *info,
					     u8 *ctx);
int btrfs_fscrypt_bio_length(struct bio *bio, u64 map_length);

#else
static inline void btrfs_fscrypt_save_extent_info(struct btrfs_path *path,
						  u8 *ctx, unsigned long size) { }

static inline int btrfs_fscrypt_load_extent_info(struct btrfs_inode *inode,
						 struct btrfs_path *path,
						 struct btrfs_key *key,
						 struct extent_map *em)
{
	return 0;
}

static inline int btrfs_fscrypt_get_disk_name(struct extent_buffer *leaf,
					      struct btrfs_dir_item *di,
					      struct fscrypt_str *qstr)
{
	return 0;
}

static inline bool btrfs_fscrypt_match_name(struct fscrypt_name *fname,
					    struct extent_buffer *leaf,
					    unsigned long de_name,
					    u32 de_name_len)
{
	if (de_name_len != fname_len(fname))
		return false;
	return !memcmp_extent_buffer(leaf, fname->disk_name.name, de_name, de_name_len);
}

static inline ssize_t btrfs_fscrypt_context_for_new_extent(struct btrfs_inode *inode,
							   struct fscrypt_extent_info *info,
							   u8 *ctx)
{
	if (!info)
		return 0;
	return -EINVAL;
}

static inline u64 btrfs_fscrypt_bio_length(struct bio *bio, u64 map_length)
{
	return map_length;
}

#endif /* CONFIG_FS_ENCRYPTION */

extern const struct fscrypt_operations btrfs_fscrypt_ops;

#endif /* BTRFS_FSCRYPT_H */
