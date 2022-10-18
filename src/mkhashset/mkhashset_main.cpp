/*

Make a hashset from a list of filenames:

find -type f | xargs sha1sum | cut -f1 -d' ' | mkhashset 'Some test hashes' 'These are test hashes.' sha1 >sha1.hset

Make a hashset and sizeset from a list of filenames:

for i in $(find -type f) ; do echo $(stat --printf=%s $i) $(md5sum $i | cut -f1 -d' ') $(sha1sum $i | cut -f1 -d' ') ; done | mkhashset 'Some test hashes' 'These are test hashes.' sizes md5 sha1 >test.hset

Make a hashset and sizeset from the NSRL:

for i in NSRLFile.*.txt.gz ; do zcat $i | ./nsrldump.py ; done | mkhashset 'NSRL' 'The NSRL!' sha1 >nsrl.hset

*/

#include <iostream>
#include <vector>

#include "hset_encoder.h"
#include "hasher/hashset.h"

int main(int argc, char** argv) {
  if (argc < 4) {
    std::cerr << "Usage: mkhashset NAME DESC TYPE...\n";
    return -1;
  }

  std::vector<SFHASH_HashAlgorithm> htypes;
  for (int i = 3; i < argc; ++i) {
// TODO: handle errors
    htypes.push_back(sfhash_hash_type(argv[i]));
  }

  write_hashset(
    argv[1],
    argv[2],
    htypes.data(),
    htypes.size(),
    std::cin,
    std::cout
  );

/*
  const size_t wlen = encode_hset(
    argv[1],
    argv[2],
    argv + 3,
    argc - 3,
    std::cin,
    std::cout
  );

  std::cerr << "wrote " << wlen << " bytes\n";
*/
  return 0;
}
