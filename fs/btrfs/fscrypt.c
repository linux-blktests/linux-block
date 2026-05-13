// SPDX-License-Identifier: GPL-2.0

#include "ctree.h"
#include "btrfs_inode.h"
#include "fscrypt.h"

const struct fscrypt_operations btrfs_fscrypt_ops = {
	.inode_info_offs = (int)offsetof(struct btrfs_inode, i_crypt_info) -
			   (int)offsetof(struct btrfs_inode, vfs_inode),
};
