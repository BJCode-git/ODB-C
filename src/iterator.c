#include <iterator.h>

void print_it(const IO_Iterator *it) {

    size_t current_vec_len = it->current_vec >= it->io_count ? 0 : it->iovec[it->current_vec].iov_len;
    printf( "\t io_count :          %zu\n"
            "\t current_vec :       %zu\n"
            "\t current_index :     %zu\n"
            "\t current_vec_len :   %zu\n",
            it->io_count,
            it->current_vec,
            it->current_index,
            current_vec_len
        );
}

void IO_Iterator_cpy(IO_Iterator *dst, const IO_Iterator *src){
    // allow to bypass const ptr affectation
    memcpy(&dst->iovec,&src->iovec,sizeof(src->iovec));
    dst->io_count        = src->io_count;
    dst->current_vec     = src->current_vec;
    dst->current_index   = src->current_index;
}


void IO_Iterator_start(IO_Iterator *it) {
    if(it == NULL) return;
    it->current_vec     = 0;
    it->current_index   = 0;

    // search for the first non empty iovec
    for(size_t i_vec = 0; i_vec < it->io_count; i_vec++){
        if(it->iovec[i_vec].iov_len > 0){
            it->current_vec = i_vec;
            break;
        }
    }
}

void IO_Iterator_end(IO_Iterator *it) {
    if (it == NULL || it->io_count == 0) return;

    for (ssize_t i = it->io_count - 1; i >= 0; i--) {
        size_t len = it->iovec[i].iov_len;

        if (it->iovec[i].iov_base != NULL && len > 0) {
            it->current_vec   = (size_t)i;
            it->current_index = len;
            return;
        }
    }

    // Aucun buffer valide, positionne à zéro
    it->current_vec = 0;
    it->current_index = 0;
}

void init_IO_Iterator(IO_Iterator *it, const struct iovec *iovec, const size_t io_count) {
    if (it == NULL || iovec == NULL) return;
    // allow to bypass const ptr affectation
    memcpy(&it->iovec,&iovec,sizeof(iovec));
    //it->iovec           = iovec;
    it->io_count        = io_count;
    // init to start (1st accessible element)
    IO_Iterator_start(it);
}

int IO_Iterator_is_start(IO_Iterator *it) {
    if (it == NULL) return -1;

    // save current position
    size_t current_vec   = it->current_vec;
    size_t current_index = it->current_index;

    // if 1st index, it's the first for sure
    if(current_vec == 0 && current_index ==0) return 1;

    // find start
    IO_Iterator_start(it);

    // return if at start
    if(it->current_vec == current_vec){
        return 1;
    }


    // restore if not already at start
    it->current_vec     = current_vec;
    it->current_index   = current_index;
    return 0;
    

   return 0;
}

int IO_Iterator_is_end(const IO_Iterator *it) {
    if (it == NULL || it->io_count == 0) return 1;

    // Vérifie si la position actuelle est au-delà des dernières données valides
    size_t vec = it->current_vec;
    size_t idx = it->current_index;

    // Trouver la dernière position lisible dans le tableau (en partant de la fin)
    for (ssize_t i = it->io_count - 1; i >= 0; i--) {
        size_t len = it->iovec[i].iov_len;

        if (it->iovec[i].iov_base != NULL && len > 0) {
            // Si l'itérateur est au-delà de cette dernière donnée
            if (vec > (size_t)i) return 1;
            if (vec == (size_t)i && idx >= len) return 1;

            // Sinon, on est encore dedans
            return 0;
        }
    }

    // Aucun buffer valide trouvé => fin atteinte
    return 1;
}

void* IO_Iterator_get(IO_Iterator *it, size_t obj_size) {
    if(it == NULL) return NULL;

    // if outbound, return NULL
    if(IO_Iterator_is_end(it)) return NULL;

    // if outbound, return NULL
    //else if(it->current_vec >= it->io_count ||
    //        it->iovec[it->current_vec].iov_len == 0) return NULL;
    //else if(it->iovec[it->current_vec].iov_len <= it->current_index) return NULL;
    
    
    // use uint8_t pointer to do some arithmetics
    uint8_t *ptr = (uint8_t *) it->iovec[it->current_vec].iov_base;
    ptr += (it->current_index * obj_size);

    return (void *)ptr;
}

void IO_Iterator_incr(IO_Iterator *it, const size_t increment) {
    if (it == NULL || it->io_count == 0) return;

    size_t remaining = increment;

    while (remaining > 0 && it->current_vec < it->io_count) {
        struct iovec *vec = &it->iovec[it->current_vec];

        if (vec->iov_base == NULL || vec->iov_len == 0) {
            it->current_vec++;
            it->current_index = 0;
            continue;
        }

        size_t available = vec->iov_len - it->current_index;

        if (remaining < available) {
            it->current_index += remaining;
            return;
        }

        // Consomme tout ce qu'il reste dans ce buffer
        remaining -= available;
        it->current_vec++;
        it->current_index = 0;
    }

    // Se placer juste après la dernière donnée valide
    while (it->current_vec < it->io_count &&
           (it->iovec[it->current_vec].iov_base == NULL || it->iovec[it->current_vec].iov_len == 0)) {
        it->current_vec++;
    }

    // Cas terminal : position au-delà du dernier élément accessible
    if (it->current_vec >= it->io_count) {
        it->current_vec = it->io_count;
        it->current_index = 0;
    }
}

void IO_Iterator_decr(IO_Iterator *it, const size_t decrement) {
    if (it == NULL || it->io_count == 0) return;

    size_t remaining = decrement;

    while (remaining > 0) {
        // Si on est déjà en dehors du tableau (après la fin), revenir sur le dernier élément valide
        if (it->current_vec >= it->io_count) {
            // Cherche la fin valide
            for (ssize_t i = it->io_count - 1; i >= 0; i--) {
                if (it->iovec[i].iov_base != NULL && it->iovec[i].iov_len > 0) {
                    it->current_vec = i;
                    it->current_index = it->iovec[i].iov_len;
                    break;
                }
            }
        }

        // Si on est en début de buffer
        if (it->current_vec == 0 && it->current_index == 0) {
            return;
        }

        if (it->current_index > 0) {
            size_t delta = MIN(remaining, it->current_index);
            it->current_index -= delta;
            remaining -= delta;
            if (remaining == 0) return;
        }

        // Aller au buffer précédent
        while (it->current_vec > 0) {
            it->current_vec--;
            struct iovec *vec = &it->iovec[it->current_vec];
            if (vec->iov_base != NULL && vec->iov_len > 0) {
                it->current_index = vec->iov_len;
                break;
            }
        }
    }

    // Ne pas aller en position invalide (négative)
    if (it->current_vec == 0 && it->current_index == 0 && remaining > 0) {
        // Début absolu atteint
        return;
    }
}


size_t IO_Iterator_memcpy(IO_Iterator *dst, IO_Iterator *src){
    if(src == NULL || dst == NULL) return 0;

    uint8_t *src_ptr = NULL;
    uint8_t *dst_ptr = NULL;
    size_t  count =0;

    // save it positions
    size_t dst_vec      = dst->current_vec,
           dst_index    = dst->current_index,
           src_vec      = src->current_vec,
           src_index    = src->current_index;

    // copy data from the iovec to the local buffer
    while( !IO_Iterator_is_end(dst) && !IO_Iterator_is_end(src)){
        src_ptr = (uint8_t*) IO_Iterator_get(src,sizeof(uint8_t));
        dst_ptr = (uint8_t*) IO_Iterator_get(dst,sizeof(uint8_t));
        
        if(NULL != dst_ptr){
            *dst_ptr = 0;
            if( NULL != src_ptr){
                *dst_ptr = *src_ptr;
                count++;
            }
        }
        
        IO_Iterator_incr(src,1);
        IO_Iterator_incr(dst,1);
    }

    // restore it positions 
    dst->current_vec    = dst_vec;
    dst->current_index  = dst_index;
    src->current_vec    = src_vec;
    src->current_index  = src_index;

    return count;
}

size_t IO_Iterator_memcpyn(IO_Iterator *dst, IO_Iterator *src,size_t max_len){
    if(src == NULL || dst == NULL) return 0;

    uint8_t *src_ptr = NULL;
    uint8_t *dst_ptr = NULL;
    size_t  count =0;

    // save it positions
    size_t dst_vec      = dst->current_vec,
           dst_index    = dst->current_index,
           src_vec      = src->current_vec,
           src_index    = src->current_index;

    // copy data from the iovec to the local buffer
    while( !IO_Iterator_is_end(dst) && !IO_Iterator_is_end(src) && count < max_len){
        src_ptr = (uint8_t*) IO_Iterator_get(src,sizeof(uint8_t));
        dst_ptr = (uint8_t*) IO_Iterator_get(dst,sizeof(uint8_t));
        
        if(NULL != dst_ptr){
            *dst_ptr = 0;
            if( NULL != src_ptr){
                *dst_ptr = *src_ptr;
                count++;
            }
        }
        
        IO_Iterator_incr(src,1);
        IO_Iterator_incr(dst,1);
    }

    // restore it positions 
    dst->current_vec    = dst_vec;
    dst->current_index  = dst_index;
    src->current_vec    = src_vec;
    src->current_index  = src_index;

    return count;
}


void IO_Iterator_print_data(IO_Iterator *it){
    if(it == NULL) return;

    //save original position
    size_t current_vec   = it->current_vec;
    size_t current_index = it->current_index;
    IO_Iterator_start(it);

    char *c = NULL;
    while(!IO_Iterator_is_end(it)){
        c = (char*) IO_Iterator_get(it,sizeof(char));
        if(NULL != c){
            if( isprint(*c) || *c == '\n'){
                printf("%c",*c);
            }
            else{
                printf("\\x%02x",*c);
            }
        }
        IO_Iterator_incr(it,1);
    }

    //restore original position
    it->current_vec   = current_vec;
    it->current_index = current_index;
}

void IO_Iterator_set(IO_Iterator *it, const size_t index) {
    if (it == NULL) return;
    IO_Iterator_start(it);
    IO_Iterator_incr(it, index);
    return;
}
