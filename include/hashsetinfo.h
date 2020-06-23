#pragma once

#include "hasher/api.h"

SFHASH_HashSetInfo* parse_header(const uint8_t* beg, const uint8_t* end);

void write_header(const SFHASH_HashSetInfo* info, uint8_t* beg, uint8_t* end);
