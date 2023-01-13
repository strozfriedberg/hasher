/*

TODO: Update examples
TODO: Determine whether we can still use stdin

Make a hashset from a list of filenames:

find -type f | xargs sha1sum | cut -f1 -d' ' | mkhashset 'Some test hashes' 'These are test hashes.' sha1 >sha1.hset

Make a hashset and sizeset from a list of filenames:

for i in $(find -type f) ; do echo $(stat --printf=%s $i) $(md5sum $i | cut -f1 -d' ') $(sha1sum $i | cut -f1 -d' ') ; done | mkhashset 'Some test hashes' 'These are test hashes.' sizes md5 sha1 >test.hset

Make a hashset and sizeset from the NSRL:

for i in NSRLFile.*.txt.gz ; do zcat $i | ./nsrldump.py ; done | mkhashset 'NSRL' 'The NSRL!' sha1 >nsrl.hset

*/

#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "hset_encoder.h"
#include "util.h"
#include "hasher/hashset.h"

int main(int argc, char** argv) {
  if (argc < 7) {
    std::cerr << "Usage: mkhashset NAME DESC TYPE... RECORDS HASHSETS INFILE OUTIFLE" << std::endl;
    return -1;
  }

  try {
    // turn off synchronization of C++ streams with C streams
    std::ios_base::sync_with_stdio(false);

    std::vector<SFHASH_HashAlgorithm> htypes;
    for (int i = 3; i < argc - 4; ++i) {
      const SFHASH_HashAlgorithm t = sfhash_hash_type(argv[i]);
      THROW_IF(
        t == SFHASH_INVALID,
        "unrecognized hash type '" << argv[i] << "'"
      );

      htypes.push_back(t);
    }

    const auto& conv = make_text_converters(htypes);

    std::cerr << "creating hset file\n";

    bool with_records = !std::strcmp(argv[argc-4], "true");
    bool with_hashsets = !std::strcmp(argv[argc-3], "true");

    const std::filesystem::path outfile = argv[argc-1];
    const std::filesystem::path infile = argv[argc-2];
    const std::filesystem::path tmpdir = ".";
    std::ifstream in(infile);

    write_hset(in, htypes, conv, argv[1], argv[2], outfile, tmpdir, with_records, with_hashsets);
  }
  catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return -1;
  }

  return 0;
}
