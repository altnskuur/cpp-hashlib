#pragma once

#include <cstddef>
#include <cstdint>

/** 
 * @brief A struct representing little-endian byte order. 
*/
namespace hashlib::detail
{
    struct little_endian
    {
        [[nodiscard]] static constexpr std::uint32_t load32(const std::uint8_t* p_bytes) noexcept
        {
            return  static_cast<std::uint32_t>(p_bytes[0])  
                  | (static_cast<std::uint32_t>(p_bytes[1]) << 8)
                  | (static_cast<std::uint32_t>(p_bytes[2]) << 16)
                  | (static_cast<std::uint32_t>(p_bytes[3]) << 24);
        }

        static constexpr void store32(std::uint8_t* p_bytes, std::uint32_t value) noexcept
        {
            p_bytes[0] = static_cast<std::uint8_t>(value);
            p_bytes[1] = static_cast<std::uint8_t>(value >> 8);
            p_bytes[2] = static_cast<std::uint8_t>(value >> 16);
            p_bytes[3] = static_cast<std::uint8_t>(value >> 24);
        }
        
        [[nodiscard]] static constexpr std::uint64_t load64(const std::uint8_t* p_bytes) noexcept
        {
            return  static_cast<std::uint64_t>(load32(p_bytes))
                  | static_cast<std::uint64_t>(load32(p_bytes + 4)) << 32;
        }

        static constexpr void store64(std::uint8_t* p_bytes, std::uint64_t value) noexcept
        {
            store32(p_bytes, static_cast<std::uint32_t>(value));
            store32((p_bytes + 4), static_cast<std::uint32_t>(value >> 32));
        }
    };

    struct big_endian
    {

    };
} // namespace hashlib::detail