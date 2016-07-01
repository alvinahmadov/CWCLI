#ifndef _SECMEM_H_
#define _SECMEM_H_
void *sec_malloc(const size_t n);
void sec_free(void *p, const size_t n);

#endif
