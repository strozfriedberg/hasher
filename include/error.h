#pragma once

#include <string>

struct SFHASH_Error;
struct LG_Error;

void fill_error(SFHASH_Error** err, const std::string& msg);

void fill_error(SFHASH_Error** err, const LG_Error* lg_err);
