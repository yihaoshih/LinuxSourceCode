#ifndef _XMALLOC_H
#define _XMALLOC_H

void *xcalloc(size_t nmemb, size_t size);
char *xstrdup(const char *s);
int xusleep(const long usec);

#endif /*_XMALLOC_H*/
