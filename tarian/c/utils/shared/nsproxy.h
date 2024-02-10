#ifndef UTLIS_SHARED_NSPROXY_H
#define UTLIS_SHARED_NSPROXY_H

// impelements the BPF_CORE to read inum(namespace id) of given nsproxy field
// ns-><field>->ns.inum
#define READ_NS_INUM_FIELD_OF(__name__)                                        \
  (unsigned int)BPF_CORE_READ(ns, __name__, ns.inum)

// ns->uts_ns.name
stain struct uts_namespace *get_uts_ns(struct nsproxy *ns) {
  return BPF_CORE_READ(ns, uts_ns);
}

// ns->uts_ns->ns.inum
stain unsigned int get_uts_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(uts_ns);
}

// ns->ipc_ns->ns.inum
stain unsigned int get_ipc_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(ipc_ns);
}

// ns->mts_ns->root->mnt_id
stain int get_mts_id(struct nsproxy *ns) {
  return BPF_CORE_READ(ns, mnt_ns, root, mnt_id);
}

// ns->mts_ns->root->mnt_id
stain const char *get_mts_devname(struct nsproxy *ns) {
  return BPF_CORE_READ(ns, mnt_ns, root, mnt_devname);
}

// ns->mnt_ns->ns.inum
stain unsigned int get_mnt_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(mnt_ns);
}

// ns->pid_ns_for_children->ns.inum
stain unsigned int get_pid_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(pid_ns_for_children);
}

// ns->net_ns->ns.inum
stain unsigned int get_net_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(net_ns);
}

// ns->time_ns->ns.inum
stain unsigned int get_time_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(time_ns);
}

// ns->time_ns_for_children->ns.inum
stain unsigned int get_time_child_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(time_ns_for_children);
}

// ns->cgroup_ns->ns.inum
stain unsigned int get_cgroup_ns_id(struct nsproxy *ns) {
  return READ_NS_INUM_FIELD_OF(cgroup_ns);
}

#endif