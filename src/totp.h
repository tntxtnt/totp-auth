#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cstdint>
#include <optional>
#include <string>

namespace totp
{
using namespace CryptoPP;
using namespace std::chrono;

namespace impl
{
    // Generate HMAC-SHAxxx hash of (key, msg)
    template <class SHA>
    std::array<byte, SHA::DIGESTSIZE>
    generateHash(const SecByteBlock& key, const SecByteBlock& msg) noexcept
    {
        HMAC<SHA> hmac(key, key.size());
        hmac.Update(msg, msg.size());
        std::array<byte, SHA::DIGESTSIZE> hash;
        hmac.Final(&hash[0]);
        return hash;
    }

    // Convert a HMAC hash to n-digits passcode string
    template <size_t HASH_LEN>
    std::string hmacHash2Passcode(const std::array<byte, HASH_LEN>& hash,
                                  int digits) noexcept
    {
        size_t offset = hash.back() & 0xF;
        // clang-format off
        int binary =
             ((hash[offset] & 0x7F) << 24) |
             ((hash[offset + 1] & 0xFF) << 16) |
             ((hash[offset + 2] & 0xFF) << 8) |
             (hash[offset + 3] & 0xFF);
        // clang-format on
        const int DIGITS_POWER[] = {1,      10,      100,      1000,     10000,
                                    100000, 1000000, 10000000, 100000000};
        int otp = binary % DIGITS_POWER[digits];
        std::string result(digits, '0');
        for (size_t i = result.size(); i--; otp /= 10)
            result[i] += otp % 10;
        return result;
    }

    // Generate code with input msg
    template <class SHA>
    std::string generateCode(const SecByteBlock& key, const SecByteBlock& msg,
                             int digits = 6) noexcept
    {
        return hmacHash2Passcode(generateHash<SHA>(key, msg), digits);
    }

    // Generate code with input timestamp
    template <class SHA>
    std::string generateCode(const SecByteBlock& key, seconds timestamp,
                             int digits = 6,
                             seconds timeStep = seconds{30}) noexcept
    {
        auto tc = timestamp / timeStep;
        SecByteBlock msg(sizeof tc);
        for (size_t i = msg.size(); i--; tc >>= 8)
            msg[i] = tc & 0xFF;
        return generateCode<SHA>(key, msg, digits);
    }

    // RFC 4648 base32 characters: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
    std::optional<unsigned> base32CharValue(char c) noexcept
    {
        if (isalpha(c))
            return (c - 1) % 32;
        if ('2' <= c && c <= '7')
            return c - 24;
        return {};
    }

    // Convert base32 string to binary:
    // - Spaces and '-' (minus/dash) will be ignored
    // - **SILENTLY** deal with commonly mistyped characters:
    //   - '0' to 'O'
    //   - '1' to 'L'
    //   - '8' to 'B'
    // Other characters that are not in the set
    // "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" will make the return value empty
    std::optional<SecByteBlock>
    googleAuthenticatorBase32Decode(const std::string& base32Str) noexcept
    {
        SecByteBlock bytes(base32Str.size() * 5 / 8); // truncate size
        unsigned bits = 0, bitCount = 0, byteIndex = 0;
        for (char c : base32Str)
        {
            // ignore spaces and dash character
            if (isspace(c) || c == '-')
                continue;
            // correct commonly mistyped characters **SILENTLY**
            if (c == '0')
                c = 'O';
            else if (c == '1')
                c = 'L';
            else if (c == '8')
                c = 'B';
            if (auto cValue = base32CharValue(c))
            {
                bits = (bits << 5) | *cValue;
                bitCount += 5;
                if (bitCount >= 8)
                    bytes[byteIndex++] = bits >> (bitCount -= 8);
            }
            else // other invalid chars will be treated as error
                return {};
        }
        // zero-filled remaining bytes or MSVC will be unhappy
        std::fill(std::begin(bytes) + byteIndex, std::end(bytes), 0);
        return bytes;
    }
} // namespace impl

// Generate TOTP key with appropriate key length
// (at least the length of HMAC output)
template <class SHA>
SecByteBlock generateKey() noexcept
{
    AutoSeededRandomPool prng;
    SecByteBlock key(SHA::DIGESTSIZE);
    prng.GenerateBlock(key, key.size());
    return key;
}

// Generate a time-based one-time passcode
template <class SHA>
std::string generateCode(const SecByteBlock& key, int digits = 6,
                         seconds timeStep = seconds{30}) noexcept
{
    auto tm = duration_cast<seconds>(system_clock::now().time_since_epoch());
    return impl::generateCode<SHA>(key, tm, digits, timeStep);
}

// Validate a time-based one-time password
template <class SHA>
bool validateCode(const std::string& code, const SecByteBlock& key,
                  int digits = 6, seconds timeStep = seconds{30}) noexcept
{
    return code == generateCode<SHA>(key, digits, timeStep);
}

// Seconds left before new time counter
duration<double> timeLeft(seconds timeStep = seconds{30}) noexcept
{
    auto now = system_clock::now().time_since_epoch();
    return timeStep - duration<double>{now % timeStep};
}

// Generate current Google authenticator code
std::optional<std::string>
googleAuthenticatorCode(const std::string& base32Key) noexcept
{
    if (auto key = impl::googleAuthenticatorBase32Decode(base32Key))
        return totp::generateCode<SHA1>(*key);
    return {};
}

} // namespace totp
