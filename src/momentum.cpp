#include "momentum.h"
#include <boost/unordered_map.hpp>
#include <iostream>

namespace bts
{
uint64_t getBirthdayHash(const uint256 &midHash, uint32_t a);

#define MAX_MOMENTUM_NONCE ( 1<<26 )
#define SEARCH_SPACE_BITS  ( 50 )
#define BIRTHDAYS_PER_HASH ( 8 )

#define DEBUG_MODE ( 1 )


///// UTILITY FUNCTIONS /////

// Compresses "hash" to within MAX_MOMENTUM_NONCE space
#define COMPRESS_CHUNK(chunk) ( chunk % MAX_MOMENTUM_NONCE )
#define COMPRESS_HASH(hash)   ( COMPRESS_CHUNK(hash[0]) )

// HASH is a wrapper for SHA512
// It creates BIRTHDAYS_PER_HASH elements, each one
//   right shifted by (64 - SEARCH_SPACE_BITS)
#define HASH(input, temp, output)                                         \
{                                                                         \
    *hash_input = input;                                                  \
    SHA512((unsigned char *)temp, sizeof(temp), (unsigned char *)output); \
    output[0] >>= (64 - SEARCH_SPACE_BITS);                               \
    output[1] >>= (64 - SEARCH_SPACE_BITS);                               \
    output[2] >>= (64 - SEARCH_SPACE_BITS);                               \
    output[3] >>= (64 - SEARCH_SPACE_BITS);                               \
    output[4] >>= (64 - SEARCH_SPACE_BITS);                               \
    output[5] >>= (64 - SEARCH_SPACE_BITS);                               \
    output[6] >>= (64 - SEARCH_SPACE_BITS);                               \
    output[7] >>= (64 - SEARCH_SPACE_BITS);                               \
}

// Given a hash chunk "cur_hash", if it exists in
//   "hash_list", return the index, else -1.
#define CONTAINS_HASH(cur_chunk, hash_list) \
    (cur_chunk == hash_list[0] ? 0 :        \
     cur_chunk == hash_list[1] ? 1 :        \
     cur_chunk == hash_list[2] ? 2 :        \
     cur_chunk == hash_list[3] ? 3 :        \
     cur_chunk == hash_list[4] ? 4 :        \
     cur_chunk == hash_list[5] ? 5 :        \
     cur_chunk == hash_list[6] ? 6 :        \
     cur_chunk == hash_list[7] ? 7 :        \
     0xFF)


#define PRINT_HASH(hash)                         \
{                                                \
std::cerr << "         0: " << hash[0] << "\n"   \
          << "         1: " << hash[1] << "\n"   \
          << "         2: " << hash[2] << "\n"   \
          << "         3: " << hash[3] << "\n"   \
          << "         4: " << hash[4] << "\n"   \
          << "         5: " << hash[5] << "\n"   \
          << "         6: " << hash[6] << "\n"   \
          << "         7: " << hash[7] << "\n";  \
}

#define COPY_HASH(src, dst) \
{                           \
    dst[0] = src[0];        \
    dst[1] = src[1];        \
    dst[2] = src[2];        \
    dst[3] = src[3];        \
    dst[4] = src[4];        \
    dst[5] = src[5];        \
    dst[6] = src[6];        \
    dst[7] = src[7];        \
}


///// MAIN HASH /////

std::vector< std::pair<uint32_t, uint32_t> > momentum_search(uint256 midHash)
{
    std::vector< std::pair<uint32_t, uint32_t> > results;

    char hash_temp[sizeof(uint256) + 4];
    memcpy((char *)&hash_temp[4], (char *)&midHash, sizeof(midHash));
    uint32_t *hash_input = (uint32_t *)hash_temp;
    uint64_t result_hash[8];

    // Floyd's cycle-finding algorithm
    uint32_t power = 1;
    uint32_t lam = 1;
    
    uint64_t turtle_hash[8];
    uint32_t turtle_nonce = 0;
    
    uint64_t hare_hash[8];
    uint32_t hare_nonce = 0;
    
    
    // Turtle = X_0
    HASH(0, hash_temp, turtle_hash);
    
    // Hare = F(X_0)
    hare_nonce = COMPRESS_HASH(result_hash);
    HASH(hare_nonce, hash_temp, hare_hash);
    
    
    while (power <= MAX_MOMENTUM_NONCE) {
        for (uint32_t chunk = 0; chunk < BIRTHDAYS_PER_HASH; ++chunk) {
            uint32_t offset = CONTAINS_HASH(hare_hash[chunk], turtle_hash);
            
            if (offset != 0xFF) {
                if (DEBUG_MODE) {
                    std::cerr << "Found hit PART 1\n";
                    std::cerr << "Hare Nonce: " << hare_nonce << " + " << chunk << "\n";
                    PRINT_HASH(hare_hash);
                    std::cerr << "Trtl Nonce: " << turtle_nonce << " + " << offset << "\n";
                    PRINT_HASH(turtle_hash);
                }
                
                break;
            }
        }
        
        
        if (power == lam) {
            COPY_HASH(hare_hash, turtle_hash);
            turtle_nonce = hare_nonce;
            power <<= 1;
            lam = 0;
        }
        
        hare_nonce = COMPRESS_HASH(hare_hash);
        HASH(hare_nonce, hash_temp, hare_hash);
        ++lam;
    }
    
    // Nothing found, give up.
    if (power >= MAX_MOMENTUM_NONCE) { return results; }
    
    
    // Rewind to find first repetition of nonces
    turtle_nonce = 0;
    HASH(turtle_nonce, hash_temp, turtle_hash);
    hare_nonce = 0;
    COPY_HASH(turtle_hash, hare_hash);
    
    // Get hare up to speed
    for (uint32_t fastforward = 0; fastforward < lam; ++fastforward) {
        hare_nonce = COMPRESS_HASH(hare_hash);
        HASH(hare_nonce, hash_temp, hare_hash);
    }
    
    // Keep stepping until they match again
    while (true) {
        for (uint32_t chunk = 0; chunk < BIRTHDAYS_PER_HASH; ++chunk) {
            uint32_t offset = CONTAINS_HASH(hare_hash[chunk], turtle_hash);
            
            if (offset != 0xFF) {
                if (DEBUG_MODE) {
                    std::cerr << "Found hit PART 2\n";
                    std::cerr << "Hare Nonce: " << hare_nonce << " + " << chunk << "\n";
                    PRINT_HASH(hare_hash);
                    std::cerr << "Trtl Nonce: " << turtle_nonce << " + " << offset << "\n";
                    PRINT_HASH(turtle_hash);
                }
                
                results.push_back( std::make_pair( hare_nonce + chunk, turtle_nonce + offset ) );
                return results;
            }
        }
        
        turtle_nonce = COMPRESS_HASH(turtle_hash);
        HASH(turtle_nonce, hash_temp, turtle_hash);
        
        hare_nonce = COMPRESS_HASH(hare_hash);
        HASH(hare_nonce, hash_temp, hare_hash);
    }
    
    
    std::cerr << "You should never be here!\n";
    
    return results;
}


uint64_t getBirthdayHash(const uint256 &midHash, uint32_t a)
{
    uint32_t index = a - (a % 8);
    char  hash_tmp[sizeof(midHash) + 4];

    memcpy(&hash_tmp[4], (char *)&midHash, sizeof(midHash));
    memcpy(&hash_tmp[0], (char *)&index, sizeof(index));

    uint64_t  result_hash[8];

    SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)&result_hash);

    uint64_t r = result_hash[a % BIRTHDAYS_PER_HASH] >> (64 - SEARCH_SPACE_BITS);

    return r;
}

bool momentum_verify(uint256 head, uint32_t a, uint32_t b)
{
    if(a == b) {
        return false;
    }

    if(a > MAX_MOMENTUM_NONCE) {
        return false;
    }

    if(b > MAX_MOMENTUM_NONCE) {
        return false;
    }

    bool r = (getBirthdayHash(head, a) == getBirthdayHash(head, b));
    return r;
}

}
