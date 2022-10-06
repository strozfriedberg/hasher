#ifndef HASHER_FUZZY_H_
#define HASHER_FUZZY_H_

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
  Fuzzy matching
******************************************************************************/

/*
 *  Input is the ssdeep CSV file format version 1.1
 *  The first line is the header
 *  ssdeep,1.1--blocksize:hash:hash,filename
 *
 *  Each line after represents the fuzzy hash of one file:
 *  blocksize:hash:hash,"filename"
 * The filename must be quoted and \-escaped.
 */

struct SFHASH_FuzzyMatcher;

struct SFHASH_FuzzyResult;

SFHASH_FuzzyMatcher* sfhash_create_fuzzy_matcher(
  const void* beg,
  const void* end
);

SFHASH_FuzzyResult* sfhash_fuzzy_matcher_compare(
  SFHASH_FuzzyMatcher* matcher,
  const void* beg,
  const void* end
);

size_t sfhash_fuzzy_result_count(const SFHASH_FuzzyResult* result);

const char* sfhash_fuzzy_result_filename(
  const SFHASH_FuzzyResult* result,
  size_t i
);

const char* sfhash_fuzzy_result_query_filename(const SFHASH_FuzzyResult* result);

int sfhash_fuzzy_result_score(const SFHASH_FuzzyResult* result, size_t i);

void sfhash_destroy_fuzzy_match(SFHASH_FuzzyResult* result);

void sfhash_destroy_fuzzy_matcher(SFHASH_FuzzyMatcher* matcher);

#ifdef __cplusplus
}
#endif

#endif /* HASHER_FUZZY_H_ */
