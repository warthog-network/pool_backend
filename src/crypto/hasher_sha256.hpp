#pragma once
#include "hash.hpp"
#include "sha2.hpp"
#include <span>


inline Hash hashSHA256(const std::span<uint8_t>& s)
{
    Hash res;
    sha256_Raw(s.data(), s.size(), res.data());
    return res;
}
