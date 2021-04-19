#ifndef __HELPERS_INT_H__
#define __HELPERS_INT_H__

struct hdr_cursor;
struct int14_shim_t;

int parse_inthdr(struct hdr_cursor *nh, struct int14_shim_t **int14_shim_t);

__u16 int_checksum(struct int14_shim_t *int14_shim_t, void *data_end);

#endif