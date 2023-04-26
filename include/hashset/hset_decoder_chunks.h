#include "hashset/hset_structs.h"

#include <cstdint>

Chunk decode_chunk(const uint8_t* beg, const uint8_t*& cur, const uint8_t* end);

void check_data_length(const Chunk& ch, uint64_t exp_len);

TableOfContents parse_ftoc(const Chunk& ch);

FileHeader parse_fhdr(const Chunk& ch);

HashsetHeader parse_hhdr(const Chunk& ch);

HashsetFilter parse_filter(const Chunk& ch);

HashsetHint parse_hint(const Chunk& ch);

ConstHashsetData parse_hdat(const Chunk& ch);

ConstRecordIndex parse_ridx(const Chunk& ch);

RecordHeader parse_rhdr(const Chunk& ch);

ConstRecordData parse_rdat(const Chunk& ch);
