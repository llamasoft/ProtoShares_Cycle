#include "momentum.h"
#include <boost/unordered_map.hpp>
#include <iostream>

namespace bts
{
#define MAX_MOMENTUM_NONCE  (1<<26)
#define SEARCH_SPACE_BITS 50
#define BIRTHDAYS_PER_HASH 8

std::vector< std::pair<uint32_t, uint32_t> > momentum_search(uint256 midHash)
{
    std::vector< std::pair<uint32_t, uint32_t> > results;

    char  hash_tmp[sizeof(midHash) + 4];
    memcpy((char *)&hash_tmp[4], (char *)&midHash, sizeof(midHash));
    uint32_t *index = (uint32_t *)hash_tmp;
    bool found_hit = false;
    
    // X
    uint32_t turtle_nonce = 0;
    uint32_t turtle_offset = 0;
    uint64_t turtle[8]; 
    
    // X'
    uint32_t hare_nonce = 0;
    uint32_t hare_offset = 0;
    uint64_t hare[8];
    
    // Defining X_0
    *index = 0;
    uint64_t result_hash[8];
    SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)result_hash);
    for (unsigned int sz = 0; sz < BIRTHDAYS_PER_HASH; ++sz) { turtle[sz] = result_hash[sz]; }
    for (unsigned int sz = 0; sz < BIRTHDAYS_PER_HASH; ++sz) { hare[sz]   = result_hash[sz]; }

    
    // Dig for a hit.
    // We can optimize out the backtrack step
    //    because we're keeping track of our nonces.
    for(uint32_t i = 0; i < (1<<(SEARCH_SPACE_BITS/2)) + 1; ++i) {
        
        // TURTLE
        // X = H(X)
        ++turtle_offset;
        if (turtle_offset >= BIRTHDAYS_PER_HASH) {
            turtle_offset = turtle_offset % BIRTHDAYS_PER_HASH;
            turtle_nonce = (turtle[0] >> (64 - SEARCH_SPACE_BITS)) % MAX_MOMENTUM_NONCE;
            
            *index = turtle_nonce;
            SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)result_hash);
            for (unsigned int sz = 0; sz < BIRTHDAYS_PER_HASH; ++sz) { turtle[sz] = result_hash[sz]; }
        }
        
        
        // HARE
        // X' = H( H(X) )
        hare_offset += 2;
        if (hare_offset >= BIRTHDAYS_PER_HASH) {
            hare_offset = hare_offset % BIRTHDAYS_PER_HASH;
            hare_nonce = (hare[0] >> (64 - SEARCH_SPACE_BITS)) % MAX_MOMENTUM_NONCE;
            
            *index = hare_nonce;
            SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)result_hash);
            for (unsigned int sz = 0; sz < BIRTHDAYS_PER_HASH; ++sz) { hare[sz] = result_hash[sz]; }
        }

        
        // Found a collision!
        if ((turtle[turtle_offset] >> (64 - SEARCH_SPACE_BITS)) == (hare[hare_offset] >> (64 - SEARCH_SPACE_BITS))) {
            found_hit = true;
            break;
        }
    }
    
    // If we stopped due to running out of entries, return the empty list
    if (found_hit == false) {
        std::cerr << "No collision found.\n";
        return results;
    }
    
    std::cerr << "Collision found!\n";
    results.push_back( std::make_pair(turtle_nonce + turtle_offset, hare_nonce + hare_offset) );
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
