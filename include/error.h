#pragma once

#include <string>

struct SFHASH_Error;

void fill_error(SFHASH_Error** err, const std::string& msg);
