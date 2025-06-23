#ifndef CHECK_H
#define CHECK_H

#include <stdio.h>
#include <stdlib.h>

#define FATAL_CHK(op, errmsg)   \
    if ( (op) < 0 ) {           \
        perror(errmsg);         \
        exit(EXIT_FAILURE);     \
    } 

#define FATAL_CHK_NULL(op, errmsg)  \
    if ( NULL == (op)) {            \
        perror(errmsg);             \
        exit(EXIT_FAILURE);         \
    }                               

#define CHK(op, errmsg,fail_return)  \
    if ( (op) < 0 ) {           \
        perror(errmsg);         \
        return fail_return;          \
    }

#define CHK_NULL(op, errmsg,fail_return) \
    if ( NULL == (op) ) {    \
            perror(errmsg);  \
            return fail_return;   \
    }

#define TCHK(op, errmsg,fail_return)  \
if ( (op) < 0 ) {           \
    perror(errmsg);         \
    return fail_return;          \
}

#define TCHK_NULL(op, errmsg,fail_return) \
if ( NULL == (op) ) {    \
        perror(errmsg);  \
        fail_return;   \
}

#endif // CHECK_H