#include "Digest.h"

#include <openssl/evp.h>
#include <stdexcept>

namespace Cryptography
{
    namespace
    {
        template <std::size_t N>
        std::array<std::uint8_t, N> DigestOneShot(std::uint8_t const* data, std::size_t size, const EVP_MD* md)
        {
            if (!md)
                throw std::runtime_error("DigestOneShot: EVP_MD is null");

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx)
                throw std::runtime_error("DigestOneShot: EVP_MD_CTX_new failed");

            std::array<std::uint8_t, N> out{};
            unsigned int outLen = 0;

            int ok = 1;
            ok &= EVP_DigestInit_ex(ctx, md, nullptr);

            // OpenSSL tolerates nullptr with size 0, but we keep it explicit.
            if (size != 0 && !data)
                ok = 0;
            else
                ok &= EVP_DigestUpdate(ctx, data, size);

            ok &= EVP_DigestFinal_ex(ctx, out.data(), &outLen);

            EVP_MD_CTX_free(ctx);

            if (!ok)
                throw std::runtime_error("DigestOneShot: EVP digest operation failed");

            if (outLen != N)
                throw std::runtime_error("DigestOneShot: unexpected digest length");

            return out;
        }
    }

    Digest::MD5Result Digest::MD5(std::uint8_t const* data, std::size_t size)
    {
        return DigestOneShot<16>(data, size, EVP_md5());
    }

    Digest::SHA1Result Digest::SHA1(std::uint8_t const* data, std::size_t size)
    {
        return DigestOneShot<20>(data, size, EVP_sha1());
    }
}
