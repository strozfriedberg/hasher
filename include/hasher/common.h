#ifndef HASHER_COMMON_H_
#define HASHER_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 Error handling
******************************************************************************/

struct SFHASH_Error {
  char* message;
};

// Frees an error struct
void sfhash_free_error(SFHASH_Error* err);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_COMMON_H_ */
