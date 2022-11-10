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

  // turn off synchronization of C++ streams with C streams
  std::ios_base::sync_with_stdio(false);

  std::vector<SFHASH_HashAlgorithm> htypes;
  for (int i = 3; i < argc; ++i) {
    const SFHASH_HashAlgorithm t = sfhash_hash_type(argv[i]);
    THROW_IF(
      t == SFHASH_INVALID,
      "unrecognized hash type '" << argv[i] << "'"
    );

    htypes.push_back(t);
  }

  std::vector<uint8_t> out;

// TODO: handle errors (e.g., bad input)
  const size_t wlen = write_hashset(
    argv[1],
    argv[2],
    htypes.data(),
    htypes.size(),
    std::cin,
    out
  );

  std::cout.write(reinterpret_cast<const char*>(out.data()), out.size());

  std::cerr << "wrote " << wlen << " bytes\n";
  return 0;
}
