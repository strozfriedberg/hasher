#include "libcrypto_hasher.h"

LibcryptoHasher::LibcryptoHasher(const EVP_MD* hfunc):
  Ctx(EVP_MD_CTX_create()),
  Hfunc(hfunc)
{
  reset();
}

LibcryptoHasher::LibcryptoHasher(const LibcryptoHasher& other):
  Ctx(EVP_MD_CTX_create()),
  Hfunc(other.Hfunc)
{
  if (!EVP_MD_CTX_copy_ex(Ctx, other.Ctx)) {
    // TODO: error!
  }
}

LibcryptoHasher& LibcryptoHasher::operator=(const LibcryptoHasher& other) {
  if (!EVP_MD_CTX_copy_ex(Ctx, other.Ctx)) {
    // TODO: error!
  }

  Hfunc = other.Hfunc;
  return *this;
}

LibcryptoHasher::~LibcryptoHasher() {
  EVP_MD_CTX_destroy(Ctx);
}

LibcryptoHasher* LibcryptoHasher::clone() const {
  return new LibcryptoHasher(*this);
}

void LibcryptoHasher::update(const uint8_t* beg, const uint8_t* end) {
  if (!EVP_DigestUpdate(Ctx, beg, end - beg)) {
    // TODO: error!
  }
}

void LibcryptoHasher::get(void* val) {
  if (!EVP_DigestFinal_ex(Ctx, static_cast<uint8_t*>(val), nullptr)) {
    // TODO: error!
  }
}

void LibcryptoHasher::reset() {
  if (!EVP_DigestInit_ex(Ctx, Hfunc, nullptr)) {
    // TODO: error!
  }
}

std::unique_ptr<HasherImpl> make_md5_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_md5()));
}

std::unique_ptr<HasherImpl> make_sha1_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha1()));
}

std::unique_ptr<HasherImpl> make_sha2_224_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha224()));
}

std::unique_ptr<HasherImpl> make_sha2_256_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha256()));
}

std::unique_ptr<HasherImpl> make_sha2_384_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha384()));
}

std::unique_ptr<HasherImpl> make_sha2_512_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha512()));
}

std::unique_ptr<HasherImpl> make_sha3_224_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha3_224()));
}

std::unique_ptr<HasherImpl> make_sha3_256_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha3_256()));
}

std::unique_ptr<HasherImpl> make_sha3_384_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha3_384()));
}

std::unique_ptr<HasherImpl> make_sha3_512_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha3_512()));
}
