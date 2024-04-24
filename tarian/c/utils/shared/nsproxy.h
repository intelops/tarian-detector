// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTLIS_SHARED_NSPROXY_H__
#define __UTLIS_SHARED_NSPROXY_H__

stain int get_mts_id(struct nsproxy *);
stain struct uts_namespace * get_uts_ns(struct nsproxy *);
stain unsigned int get_uts_ns_id(struct nsproxy *);
stain unsigned int get_ipc_ns_id(struct nsproxy *);
stain const char *get_mts_devname(struct nsproxy *);
stain unsigned int get_mnt_ns_id(struct nsproxy *);
stain unsigned int get_pid_ns_id(struct nsproxy *);
stain unsigned int get_net_ns_id(struct nsproxy *);
stain unsigned int get_time_ns_id(struct nsproxy *);
stain unsigned int get_time_child_ns_id(struct nsproxy *);
stain unsigned int get_cgroup_ns_id(struct nsproxy *);

/**
 * @brief Read inum field of given nsproxy field
 *
 * This macro is a helper to read the inum field of a given nsproxy field
 * ns-><field>->ns.inum
 *
 * @param[in] __name__ The name of the nsproxy field to read from
 *
 * @return The namespace id of the given field
 */
#define READ_NS_INUM_FIELD_OF(__name__)                                        \
  (unsigned int)BPF_CORE_READ(ns, __name__, ns.inum)

/**
 * @brief Get uts_namespace pointer from nsproxy
 *
 * This function reads the uts_ns field of the given nsproxy and returns its
 * value, ns->uts_ns.name
 * 
 * @param[in] ns The nsproxy to read the uts_ns field from
 *
 * @return The uts_namespace pointer of the given nsproxy
 */
stain struct uts_namespace *get_uts_ns(struct nsproxy *ns) {
  return BPF_CORE_READ(ns, uts_ns);
}

/**
 * @brief Get uts_namespace id from nsproxy
 *
 * This function reads the inum field of the uts_ns field of the given nsproxy
 * ns->uts_ns->ns.inum
 *
 * @param[in] ns The nsproxy to read the uts_ns field from
 *
 * @return The uts_namespace id of the given nsproxy
 */
stain unsigned int get_uts_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(uts_ns);
}

/**
 * @brief Get ipc_namespace id from nsproxy
 *
 * This function reads the inum field of the ipc_ns field of the given nsproxy
 * ns->ipc_ns->ns.inum
 *
 * @param[in] ns The nsproxy to read the ipc_ns field from
 *
 * @return The ipc_namespace id of the given nsproxy
 */
stain unsigned int get_ipc_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(ipc_ns);
}

/**
 * @brief Get mts_namespace id from nsproxy
 *
 * This function reads the mnt_id field of the root field of the mnt_ns field
 * of the given nsproxy ns->mnt_ns->root->mnt_id
 *
 * @param[in] ns The nsproxy to read the mnt_ns field from
 *
 * @return The mts_namespace id of the given nsproxy
 */
stain int get_mts_id(struct nsproxy *ns) {
  return BPF_CORE_READ(ns, mnt_ns, root, mnt_id);
}

/**
 * @brief Get device name of the mts_namespace from the given nsproxy
 *
 * This function reads the mnt_devname field of the root field of the mnt_ns
 * field of the given nsproxy ns->mnt_ns->root->mnt_devname
 *
 * @param[in] ns The nsproxy to read the mnt_ns field from
 *
 * @return The device name of the mts_namespace of the given nsproxy
 */
stain const char *get_mts_devname(struct nsproxy *ns) {
  return BPF_CORE_READ(ns, mnt_ns, root, mnt_devname);
}

/**
 * @brief Get mount namespace id from nsproxy
 *
 * This function reads the inum field of the mount_ns field of the given nsproxy
 * ns->mnt_ns->ns.inum
 *
 * @param[in] ns The nsproxy to read the mnt_ns field from
 *
 * @return The mount namespace id of the given nsproxy
 */
stain unsigned int get_mnt_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(mnt_ns);
}

/**
 * @brief Get pid_namespace id from nsproxy
 *
 * This function reads the inum field of the pid_ns_for_children field of the
 * given nsproxy ns->pid_ns_for_children->ns.inum
 *
 * @param[in] ns The nsproxy to read the pid_ns_for_children field from
 *
 * @return The pid_namespace id of the given nsproxy
 */
stain unsigned int get_pid_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(pid_ns_for_children);
}

/**
 * @brief Get network namespace id from nsproxy
 *
 * This function reads the inum field of the net_ns field of the given nsproxy
 * ns->net_ns->ns.inum
 *
 * @param[in] ns The nsproxy to read the net_ns field from
 *
 * @return The network namespace id of the given nsproxy
 */
stain unsigned int get_net_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(net_ns);
}

/**
 * @brief Get time namespace id from nsproxy
 *
 * This function reads the inum field of the time_ns field of the given nsproxy
 * ns->time_ns->ns.inum
 *
 * @param[in] ns The nsproxy to read the time_ns field from
 *
 * @return The time namespace id of the given nsproxy
 */
stain unsigned int get_time_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(time_ns);
}

/**
 * @brief Get time_for_children namespace id from nsproxy
 *
 * This function reads the inum field of the time_ns_for_children field of the
 * given nsproxy ns->time_ns_for_children->ns.inum
 *
 * @param[in] ns The nsproxy to read the time_ns_for_children field from
 *
 * @return The time_for_children namespace id of the given nsproxy
 */
stain unsigned int get_time_child_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(time_ns_for_children);
}

/**
 * @brief Get cgroup namespace id from nsproxy
 *
 * This function reads the inum field of the cgroup_ns field of the given nsproxy
 * ns->cgroup_ns->ns.inum
 *
 * @param[in] ns The nsproxy to read the cgroup_ns field from
 *
 * @return The cgroup namespace id of the given nsproxy
 */
stain unsigned int get_cgroup_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(cgroup_ns);
}

#endif