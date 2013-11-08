#include "momentum.h"
#include <boost/unordered_map.hpp>
#include <iostream>

namespace bts
{
#define MAX_MOMENTUM_NONCE  (1<<26)
#define SEARCH_SPACE_BITS 50
#define BIRTHDAYS_PER_HASH 8

// I'm a terrible person.
#define UPDATE_HASH(varname)                                                                   \
    if (varname##_offset >= BIRTHDAYS_PER_HASH) {                                              \
        varname##_offset = varname##_offset % BIRTHDAYS_PER_HASH;                              \
        varname##_nonce = varname##_minhash;                                                   \
                                                                                               \
        *index = varname##_nonce;                                                              \
        SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)result_hash);     \
                                                                                               \
        varname##_minhash = result_hash[0];                                                    \
        for (unsigned int sz = 0; sz < BIRTHDAYS_PER_HASH; ++sz) {                             \
            if (result_hash[sz] < varname##_minhash) { varname##_minhash = result_hash[sz]; }  \
            varname##_hash[sz] = result_hash[sz];                                                   \
        }                                                                                      \
    }

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
    uint64_t turtle_minhash = 0;
    uint64_t turtle_hash[8]; 
    
    // X'
    uint32_t hare_nonce = 0;
    uint32_t hare_offset = 0;
    uint64_t hare_minhash = 0;
    uint64_t hare_hash[8];
    
    // Defining X_0
    *index = 0;
    uint64_t result_hash[8];
    SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)result_hash);
    turtle_minhash = result_hash[0];
    hare_minhash = result_hash[0];
    for (unsigned int sz = 0; sz < BIRTHDAYS_PER_HASH; ++sz) {
        turtle_hash[sz] = result_hash[sz];
        hare_hash[sz] = result_hash[sz];
        
        if (result_hash[sz] < turtle_minhash) { 
            turtle_minhash = result_hash[sz];
            hare_minhash = result_hash[sz];
        }
    }

    
    // Step 1: dig for a hit
    // Not using 2^(SEARCH_SPACE_BITS/2)
    uint32_t i;
    for(i = 0; i < MAX_MOMENTUM_NONCE; ++i) {
        
        // TURTLE
        // X = H(X)
        ++turtle_offset;
        UPDATE_HASH(turtle);
        
        
        // HARE
        // X' = H( H(X) )
        hare_offset += 2;
        UPDATE_HASH(hare);

        
        // Found a collision!
        if ((turtle_hash[turtle_offset] >> (64 - SEARCH_SPACE_BITS)) == (hare_hash[hare_offset] >> (64 - SEARCH_SPACE_BITS))) {
            if (turtle_nonce != hare_nonce && turtle_offset != hare_offset) {
                found_hit = true;
                break;
            }
        }
    }
    
    // If we stopped due to running out of entries, return the empty list
    if (found_hit == false) {
        std::cerr << "No collision found.\n";
        return results;
    }
    
    
    // DEBUG
    std::cerr << "Collision found!\n";
    std::cerr << "   Iteration:     " << i << "\n";
    std::cerr << "   Turtle Nonce:  " << turtle_nonce  << "\n";
    std::cerr << "   Turtle Offset: " << turtle_offset << "\n";
    std::cerr << "   Turtle Hash:   " << (turtle_hash[turtle_offset] >> (64 - SEARCH_SPACE_BITS)) << "\n";
    std::cerr << "   Turtle Nonce Valid: " << (turtle_nonce < MAX_MOMENTUM_NONCE) << "\n";
    std::cerr << "   Hare Nonce:    " << hare_nonce  << "\n";
    std::cerr << "   Hare Offset:   " << hare_offset << "\n";
    std::cerr << "   Hare Hash:     " << (hare_hash[hare_offset] >> (64 - SEARCH_SPACE_BITS)) << "\n";
    std::cerr << "   Hare Nonce Valid:   " << (hare_nonce < MAX_MOMENTUM_NONCE) << "\n";
    std::cerr << "\n";
    
    results.push_back( std::make_pair(turtle_nonce + turtle_offset, hare_nonce + hare_offset) );
    return results;
    
    
    ////////////////////////////////////////////////
    
    // Set X' = X
    hare_nonce = turtle_nonce;
    hare_offset = turtle_offset;
    for (unsigned int sz = 0; sz < BIRTHDAYS_PER_HASH; ++sz) { hare_hash[sz] = turtle_hash[sz]; }
    
    // Reset X = X_0
    turtle_nonce = 0;
    turtle_offset = 0;
    *index = 0;
    SHA512((unsigned char *)hash_tmp, sizeof(hash_tmp), (unsigned char *)result_hash);
    for (unsigned int sz = 0; sz < BIRTHDAYS_PER_HASH; ++sz) { turtle_hash[sz] = result_hash[sz]; }
    
    
    // Step 2: find where the hit came from
    uint32_t j;
    for (j = 0; j < i; ++j) {
        if ((turtle_hash[turtle_offset] >> (64 - SEARCH_SPACE_BITS)) == (hare_hash[hare_offset] >> (64 - SEARCH_SPACE_BITS))) {
            results.push_back( std::make_pair(turtle_nonce + turtle_offset, hare_nonce + hare_offset) );
            std::cerr << "WOOT WOOT!\n";
            std::cerr << "   Iteration:     " << j << "\n";
            std::cerr << "   Turtle Nonce:  " << turtle_nonce  << "\n";
            std::cerr << "   Turtle Offset: " << turtle_offset << "\n";
            std::cerr << "   Turtle Hash:   " << (turtle_hash[turtle_offset] >> (64 - SEARCH_SPACE_BITS)) << "\n";
            std::cerr << "   Hare Nonce:    " << hare_nonce  << "\n";
            std::cerr << "   Hare Offset:   " << hare_offset << "\n";
            std::cerr << "   Hare Hash:     " << (hare_hash[hare_offset] >> (64 - SEARCH_SPACE_BITS)) << "\n";
            return results;
        }
        
        // TURTLE
        // X = H(X)
        ++turtle_offset;
        UPDATE_HASH(turtle);
        
        
        // HARE
        // X' = H(X)
        ++hare_offset;
        UPDATE_HASH(hare);
    }
    

    std::cerr << "I have no idea how you got here and it terrifies me.\n";
    std::cerr << "   Iteration:     " << j << "\n";
    std::cerr << "   Turtle Nonce:  " << turtle_nonce  << "\n";
    std::cerr << "   Turtle Offset: " << turtle_offset << "\n";
    std::cerr << "   Turtle Hash:   " << (turtle_hash[turtle_offset] >> (64 - SEARCH_SPACE_BITS)) << "\n";
    std::cerr << "   Hare Nonce:    " << hare_nonce  << "\n";
    std::cerr << "   Hare Offset:   " << hare_offset << "\n";
    std::cerr << "   Hare Hash:     " << (hare_hash[hare_offset] >> (64 - SEARCH_SPACE_BITS)) << "\n";
    
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
