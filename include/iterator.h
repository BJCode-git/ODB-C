#ifndef ITERATOR_H
#define ITERATOR_H

#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <stdint.h>
#include <ctype.h>


#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))

typedef struct {
    struct iovec*   iovec;
    size_t          io_count;
    size_t          current_vec;
    size_t          current_index;
}IO_Iterator;

void print_it(const IO_Iterator *it);

void IO_Iterator_cpy(IO_Iterator *dst, const IO_Iterator *src);

void IO_Iterator_start(IO_Iterator *it);

void IO_Iterator_end(IO_Iterator *it);

void init_IO_Iterator(IO_Iterator *it, const struct iovec *iovec, const size_t io_count);

int IO_Iterator_is_start(IO_Iterator *it);
int IO_Iterator_is_end(const IO_Iterator *it);

void* IO_Iterator_get(IO_Iterator *it, size_t obj_size);

void IO_Iterator_incr(IO_Iterator *it, const size_t increment);

void IO_Iterator_decr(IO_Iterator *it, const size_t decrement);

size_t IO_Iterator_memcpy(IO_Iterator *dst, IO_Iterator *src);

size_t IO_Iterator_memcpyn(IO_Iterator *dst, IO_Iterator *src,size_t max_len);

void IO_Iterator_print_data(IO_Iterator *it);

void IO_Iterator_set(IO_Iterator *it, const size_t index);

#define DECL_FN_TEST_SEQUENCE(TYPE, FMT_SPEC) \
size_t test_sequence_##TYPE(IO_Iterator *it, ssize_t *seq, TYPE *seq_results, size_t seq_len) { \
    TYPE *data = NULL;                                                                  \
    size_t res = 0;                                                                     \
    if (it == NULL || seq == NULL || seq_results == NULL || seq_len == 0) return 0;     \
    /*print_it(it);*/                                                                   \
                                                                                        \
    for (size_t i = 0; i < seq_len; i++) {                                              \
        if (seq[i] > 0) {                                                               \
            printf("\tit += %zd :\n", seq[i]);                                          \
            IO_Iterator_incr(it, seq[i]);                                               \
        }                                                                               \
        else if (seq[i] < 0) {                                                          \
            printf("\tit -= %zd :\n", -seq[i]);                                         \
            IO_Iterator_decr(it, -seq[i]);                                              \
        }                                                                               \
        else {                                                                          \
            printf("\tit += 0 :\n");                                                    \
            /*print_it(it);*/                                                           \
            data = (TYPE *) IO_Iterator_get(it, sizeof(TYPE));                          \
            if (data != NULL) {                                                         \
                res += seq_results[i] == *data;                                         \
            }                                                                           \
            else return res;                                                            \
            printf("\tit -= 0 :\n");                                                    \
        }                                                                               \
                                                                                        \
        /*print_it(it);*/                                                               \
        data = (TYPE *) IO_Iterator_get(it, sizeof(TYPE));                              \
        if (data != NULL) {                                                             \
            res = seq_results[i] == *data ? res +1 : res;                               \
        /*printf(FMT_SPEC "vs " FMT_SPEC  , *data, seq_results[i]);*/                   \
        }                                                                               \
        else return res;                                                                \
    }                                                                                   \
                                                                                        \
    return res;                                                                         \
}



/*
void IO_Iterator_incr(IO_Iterator *it, const size_t increment) {
    size_t total_incr   = 0;
    size_t current_incr = 0;
    size_t temp_vec     = it->current_vec;
    size_t temp_index   = it->current_index;
    uint8_t shift       = 0;

    if (it == NULL) return;

    // if outbound, place it to start
    IO_Iterator_is_start(it);

    while(total_incr < increment && it->current_vec < it->io_count) {

        // so here , we have this condition : 
        // it->iovec[it->current_vec].iov_len + 1 >= it->current_index >= 0
        
        current_incr = MIN(increment - total_incr, it->iovec[it->current_vec].iov_len - it->current_index);
        total_incr  += current_incr;

        it->current_index  += current_incr;

        // save last acceptable index
        temp_index   = it->current_index;
        temp_vec     = it->current_vec;
        shift        = 0;
        if(it->current_index >= it->iovec[it->current_vec].iov_len){
            temp_index = temp_index == 0 ? 0 : temp_index -1;
            shift      = 1;
        }

        // while we have reach the end of the current buffer or accessing an empty buffer, 
        // we pass to the next one
        // use lazy evaluation
        while(it->current_vec < it->io_count && it->iovec[it->current_vec].iov_len <= it->current_index){
            it->current_index = 0;
            it->current_vec++;
        }
        // if had to go to the next buffer and find a non empty buffer
        if(shift == 1 && it->current_vec < it->io_count){
            temp_index = 0;
            temp_vec   = it->current_vec;
        }

    }

    it->current_vec     = temp_vec;
    it->current_index   = temp_index;

    // if we reached out of bound without previous acceptable index
    // bring back to last element if outbound
    IO_Iterator_is_end(it);
}

void IO_Iterator_incr(IO_Iterator *it, const size_t increment) {
    if (it == NULL || it->io_count == 0) return;

    size_t remaining = increment;

    while (remaining > 0 && it->current_vec < it->io_count) {
        struct iovec *vec = &it->iovec[it->current_vec];

        // Si le buffer courant est vide ou invalide
        if (vec->iov_base == NULL || vec->iov_len == 0) {
            it->current_vec++;
            it->current_index = 0;
            continue;
        }

        size_t available = vec->iov_len - it->current_index;

        // Si on peut consommer dans ce buffer
        if (remaining < available) {
            it->current_index += remaining;
            return;
        }

        // Sinon, on consomme tout ce qu'il reste et passe au suivant
        remaining -= available;
        it->current_vec++;
        it->current_index = 0;
    }

    // Si on a dépassé les buffers disponibles, se placer après la dernière position valide
    while (it->current_vec < it->io_count &&
           (it->iovec[it->current_vec].iov_base == NULL || it->iovec[it->current_vec].iov_len == 0)) {
        it->current_vec++;
    }

    // Si on est hors du tableau, corriger l’index
    if (it->current_vec >= it->io_count) {
        it->current_vec = it->io_count;
        it->current_index = 0;
    }
}


void IO_Iterator_decr(IO_Iterator *it, const size_t decrement) {
    size_t total_decr   = 0;
    size_t current_decr = 0;

    if (it == NULL) return;

    IO_Iterator_is_end(it);

    while(total_decr < decrement && !IO_Iterator_is_start(it)){
        current_decr        = MIN(decrement - total_decr, it->current_index);
        it->current_index  -= current_decr;
        total_decr         += current_decr;

        // change to previous buffer until finding 
        // a buffer with non-zero length
        while(it->current_index == 0 && it->current_vec > 0){
            it->current_vec--;
            it->current_index = it->iovec[it->current_vec].iov_len;
            if (it->current_index != 0){
                // set index to last element of the iovec
                it->current_index--;
                total_decr++;
                break;
            }
        }
    }
}
*/


#endif // ITERATOR_H