/* Test-only SDK oracle for the Rust FFI layouts in ../macos.rs. */
#include <stddef.h>
#include <stdio.h>
#include <sys/proc_info.h>

#define VALUE(value) printf("%zu\n", (size_t)(value))
int main(void) {
    VALUE(sizeof(struct socket_fdinfo));
    VALUE(_Alignof(struct socket_fdinfo));
    VALUE(offsetof(struct socket_fdinfo, psi));
    VALUE(sizeof(struct proc_fileinfo));
    VALUE(sizeof(struct vinfo_stat));
    VALUE(sizeof(struct socket_info));
    VALUE(_Alignof(struct socket_info));
    VALUE(offsetof(struct socket_info, soi_so));
    VALUE(offsetof(struct socket_info, soi_type));
    VALUE(offsetof(struct socket_info, soi_family));
    VALUE(offsetof(struct socket_info, soi_kind));
    VALUE(offsetof(struct socket_info, soi_proto));
    VALUE(sizeof(((struct socket_info *)0)->soi_proto));
    VALUE(_Alignof(__typeof__(((struct socket_info *)0)->soi_proto)));
    VALUE(offsetof(struct un_sockinfo, unsi_conn_so));
    VALUE(sizeof(struct un_sockinfo));
    VALUE(_Alignof(struct un_sockinfo));
    VALUE(sizeof(struct sockbuf_info));
    VALUE(sizeof(struct proc_fdinfo));
    VALUE(offsetof(struct proc_fdinfo, proc_fdtype));
    return 0;
}
