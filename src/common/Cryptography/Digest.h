#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace Cryptography
{
    class Digest
    {
    public:
        using MD5Result  = std::array<std::uint8_t, 16>;
        using SHA1Result = std::array<std::uint8_t, 20>;

        // One-shot digests (C++14 friendly)
        static MD5Result  MD5(std::uint8_t const* data, std::size_t size);
        static SHA1Result SHA1(std::uint8_t const* data, std::size_t size);
    };
}
