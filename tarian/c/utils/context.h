#ifndef __UTILS_CONTEXT_H__
#define __UTILS_CONTEXT_H__

#include "index.h"

// stain int read_cwd_into(struct path *path, u8 *buf) {
//   /*
//     Data saved to buf: [start index of string 2byte][size of the string 2byte]....[...string....]
//   */
//   char slash = '/';
//   int zero = 0;
//   int sz = 0;

//   struct path file_path;
//   bpf_probe_read(&file_path, sizeof(struct path), path);

//   struct dentry *dentry = file_path.dentry;
//   struct vfsmount *vfsmnt = file_path.mnt;

//   struct mount *mnt_parent_p;
//   struct mount *mnt_p = real_mount(vfsmnt);

//   bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

//   struct dentry *mnt_root;
//   struct dentry *d_parent;
//   struct qstr d_name;

//   unsigned int len = 0;
//   short cursor = MAX_STRING_SIZE - 1; // current index in buffer. starts with 4095
//   short str_len = 0; // total size of string written to buffer

// #pragma unroll
//   for (int i = 0; i < MAX_PATH_LOOP /* 20 */; i++) {
//     mnt_root = get_mnt_root_ptr(vfsmnt);
//     d_parent = get_d_parent_ptr(dentry);

//     if (dentry == mnt_root || dentry == d_parent) {
//       if (dentry != mnt_root) {
//         break;
//       }
//       if (mnt_p != mnt_parent_p) {
//         bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
//         bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
//         bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
//         vfsmnt = &mnt_p->mnt;

//         continue;
//       }

//       break;
//     }

//     d_name = get_d_name_from_dentry(dentry);
//     len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);

//     // Check buffer capacity
//     if ((MAX_STRING_SIZE - str_len - sizeof(int) /* for string index and len */ - 1 /* for null byte at the end*/) < MAX_STRING_SIZE) {
//       cursor -= len;
//       sz = bpf_probe_read_str(&(buf[cursor & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
//     } else
//       break;

//     if (sz > 1) {
//       str_len += sz;
//       bpf_probe_read(&(buf[(cursor + len - 1) & (MAX_STRING_SIZE - 1)]), 1, &slash);
//     } else
//       break;

//     dentry = d_parent;
//   }

//   if (cursor == MAX_STRING_SIZE - 1) {
//     d_name = get_d_name_from_dentry(dentry);
//     len = (d_name.len) & (MAX_STRING_SIZE - 1);
//     cursor -= len;
//     sz = bpf_probe_read_str(&(buf[cursor & (MAX_STRING_SIZE - 1)]), MAX_STRING_SIZE, (void *)d_name.name);
//     str_len += sz;
//   } else {
//     cursor -= 1;
//     bpf_probe_read(&(buf[cursor & (MAX_STRING_SIZE - 1)]), 1, &slash);
//     bpf_probe_read(&(buf[MAX_STRING_SIZE - 1]), 1, &zero);
//     str_len += 2; /* 1 for null termination + 1 for adding slash in the begning of the string */
//   }

//   // write start index of string to buffer
//   bpf_probe_read(&(buf[0]), sizeof(short), &cursor);
//   bpf_probe_read(&(buf[2]), sizeof(short), &str_len);

//   // bpf_printk("string: cwd %d, %d", cursor, str_len);

//   // u32 ret = ((u32)cursor << 16) | str_len;

//   return OK;
// };

// task->nsproxy->uts_ns->name
// stain int read_node_info_into(node_info_t *ni, struct task_struct *t) {
//   if (ni == NULL)
//     return TDCE_NULL_POINTER;

//   struct uts_namespace *uts_ns = get_uts_ns(get_task_nsproxy(t));
//   BPF_CORE_READ_INTO(ni, uts_ns, name);

//   return TDC_SUCCESS;
// }

#endif