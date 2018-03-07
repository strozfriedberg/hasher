#include "libcrypto_hasher.h"

LibcryptoHasher::LibcryptoHasher(const EVP_MD* hfunc):
  ctx(EVP_MD_CTX_create()), hfunc(hfunc)
{
  reset();
}

LibcryptoHasher::LibcryptoHasher(const LibcryptoHasher& other):
  ctx(EVP_MD_CTX_create()), hfunc(other.hfunc)
{
  if (!EVP_MD_CTX_copy(ctx, other.ctx)) {
    // TODO: error!
  }
}

LibcryptoHasher& LibcryptoHasher::operator=(const LibcryptoHasher& other) {
  if (!EVP_MD_CTX_copy(ctx, other.ctx)) {
    // TODO: error!
  }

  hfunc = other.hfunc;
  return *this;
}

LibcryptoHasher::~LibcryptoHasher() {
  EVP_MD_CTX_destroy(ctx);
}

LibcryptoHasher* LibcryptoHasher::clone() const {
  return new LibcryptoHasher(*this);
}

void LibcryptoHasher::update(const uint8_t* beg, const uint8_t* end) {
  if (!EVP_DigestUpdate(ctx, beg, end - beg)) {
    // TODO: error!
  }
}

void LibcryptoHasher::get(void* val) {
  if (!EVP_DigestFinal_ex(ctx, static_cast<uint8_t*>(val), nullptr)) {
    // TODO: error!
  }
}

void LibcryptoHasher::reset() {
  if (!EVP_DigestInit(ctx, hfunc)) {
    // TODO: error!
  }
}

std::unique_ptr<HasherImpl> make_md5_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_md5()));
}

std::unique_ptr<HasherImpl> make_sha1_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha1()));
}

std::unique_ptr<HasherImpl> make_sha256_hasher() {
  return std::unique_ptr<LibcryptoHasher>(new LibcryptoHasher(EVP_sha256()));
}
