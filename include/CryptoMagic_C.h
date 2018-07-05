//
// Created by Tigran on 7/6/18.
//

#ifndef CRYPTOMAIC_CRYPTOMAGIC_H
#define CRYPTOMAIC_CRYPTOMAGIC_H

/**
 * \brief Making any memory allocations here needed to operate this library from C interface
 */
extern "C" void cryptomagic_init();

/**
 * \brief For interfacing with C and other languages we need higher level functions and non class based pointers
 * This function initiates CryptoMagic class object and turning it as a void * pointer to keep it inside other
 * languages contexts, where they can reference to that class over our C API, just providing that void * memory pointer
 * @return CryptoMagic pointer converted to (void *)
 */
extern "C" void * cryptomagic_new();

/**
 * \brief Cleaning up all allocations and main CryptoMagic object allocation
 * NOTE: this will crash if badly if we will pass wrong pointer from other languages, BUT that's on owr own risk!
 * @param cm
 */
extern "C" void cryptomagic_clear(void *cm_ptr);

#endif //CRYPTOMAIC_CRYPTOMAGIC_H
