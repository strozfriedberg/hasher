#ifndef ENTROPY_C_API_H_
#define ENTROPY_C_API_H_

#ifdef __cplusplus
extern "C" {
#endif

struct SFHASH_Entropy;

SFHASH_Entropy* sfhash_create_entropy();

SFHASH_Entropy* sfhash_clone_entropy(const SFHASH_Entropy* entropy);

void sfhash_update_entropy(SFHASH_Entropy* entropy, const void* beg, const void* end);

double sfhash_get_entropy(SFHASH_Entropy* entropy);

void sfhash_accumulate_entropy(SFHASH_Entropy* sum, const SFHASH_Entropy* addend);

void sfhash_reset_entropy(SFHASH_Entropy* entropy);

void sfhash_destroy_entropy(SFHASH_Entropy* entropy);

#ifdef __cplusplus
}
#endif

#endif /* ENTROPY_C_API_H_ */
