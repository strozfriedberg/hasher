#pragma once

#include "hasher/api.h"
#include "hashsetdata.h"
#include "util.h"

#include "hsd_impls/radius_hsd.h"

#include <ctime>
#include <cstring>
#include <memory>

char* to_iso8601(std::time_t tt);
