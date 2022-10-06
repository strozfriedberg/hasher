#ifndef HASHER_HEX_H_
#define HASHER_HEX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
  Hex encoding and decoding
******************************************************************************/

// Converts len bytes of src to a hexadecimal string dest.
// The length of dest will be 2*len.
void sfhash_hex(char* dest, const void* src, size_t len);

// Converts a hexadecimal string src of length len to bytes dest.
// Returns true on success, false on bad input (either src had a
// character not in [0-9A-Za-z] or src had an odd length).
bool sfhash_unhex(uint8_t* dest, const char* src, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_HEX_H_ */
