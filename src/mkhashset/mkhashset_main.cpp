/*

Make a hashset from a list of filenames:

find -type f | xargs sha1sum | cut -f1 -d' ' | mkhashset 'Some test hashes' 'These are test hashes.' sha1 >sha1.hset

Make a hashset and sizeset from a list of filenames:

for i in $(find -type f) ; do echo $(stat --printf=%s $i) $(md5sum $i | cut -f1 -d' ') $(sha1sum $i | cut -f1 -d' ') ; done | mkhashset 'Some test hashes' 'These are test hashes.' sizes md5 sha1 >test.hset

Make a hashset and sizeset from the NSRL:

for i in NSRLFile.*.txt.gz ; do zcat $i | ./nsrldump.py ; done | mkhashset 'NSRL' 'The NSRL!' sha1 >nsrl.hset

*/

#include <iostream>

#include "hset_encoder.h"

int main(int argc, char** argv) {
  if (argc < 4) {
    std::cerr << "Usage: mkhashset NAME DESC TYPE...\n";
    return -1;
  }

  const size_t wlen = run(
    argv[1], argv[2], argv + 3, argc - 3, std::cin, std::cout
  );

  std::cerr << "wrote " << wlen << " bytes\n";
  return 0;
}
