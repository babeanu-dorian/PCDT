#ifndef HEAESCMAC_SEC_PARAMS_H
#define HEAESCMAC_SEC_PARAMS_H

#include <vector>

namespace HeAesCmac {
    struct SecurityParams {
        long m;                   // Cyclotomic polynomial - defines phi(m).
        long r;                   // Hensel lifting (default = 1).
        long cm;                  // Ring constant.
        long k;                   // Number of bits of the modulus chain.
        long c;                   // Number of columns of Key-Switching matrix (typically 2 or 3).
        long hwsk;                // Hamming weight of the secret key.
        std::vector<long> mvec;   // Factorisation of m required for bootstrapping.
        std::vector<long> gens;   // Generating set of Zm* group.
        std::vector<long> ords;   // Orders of the previous generators.
    };
}

#endif /* !HEAESCMAC_SEC_PARAMS_H */