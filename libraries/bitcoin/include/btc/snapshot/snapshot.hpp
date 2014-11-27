#pragma once

#include <array>
#include <vector>
#include <fstream>
#include <memory>
#include <stdint.h>


namespace btc { namespace snapshot {
    
#define BTC_SNAPSHOT_HEADER_OFFSET 4 + 20 + 32 + 8 + 8 + 8 + 8 + 8 + 8

/*
Version            01 00 00 00                                                 4 bytes (uint32)
MerkleRoot         Merkle root of claim entries (hash160)                      20 bytes
Blockhash          hash of Bitcoin block that snapshot was taken from          32 bytes
TotalClaimValue    the sum of all the claims (in satoshis)                     8 bytes (uint64)
NumClaims          the number of claims to follow                              8 bytes (uint64)
P2PkHOffset        the file offset in bytes for P2PkH claim section            8 bytes (uint64) 
P2SHOffset         the file offset in bytes for P2SH claim section             8 bytes (uint64)      
NatMultisigOffset  the file offset in bytes for native multisig claim section  8 bytes (uint64)      
RawScriptOffset    the file offset in bytes for raw script claim section       8 bytes (uint64)               
ClaimEntries       the list of claims  (sorted)                                <Claimsize> number of claims
 */
struct snapshot_header {
    uint32_t            version;
    std::array<char,20> merkle_root;
    std::array<char,32> block_hash;
    uint64_t            total_claim_value;
    uint64_t            num_claims;
    uint64_t            p2pkh_offset;
    uint64_t            p2sh_offset;
    uint64_t            multisig_offset;
    uint64_t            raw_script_offset;
    
    snapshot_header ();
};
std::ostream& operator<<(std::ostream &os, const snapshot_header &header);
std::istream& operator>>(std::istream &is, snapshot_header &header);
void prettyPrint (const snapshot_header &header);

struct p2pkh {
    std::array<char,20> hash;
    uint64_t            amount;
    
    p2pkh ();
    p2pkh (std::array<char,20> _hash, uint64_t _amount);
    p2pkh (const p2pkh& other);
};
std::ostream& operator<<(std::ostream &os, const p2pkh &entry);
std::istream& operator>>(std::istream &is, p2pkh &entry);
void prettyPrint (const p2pkh &entry);

struct snapshot {
    snapshot_header         header;
    std::vector<p2pkh>      p2pkh_entries;
    std::ifstream*          ifstream;
    
    snapshot ();
    snapshot (std::ifstream* _ifstream);
    void add_p2pkh (const p2pkh& entry);
    p2pkh* get_p2pkh (const std::array<char,20> &hash);
    p2pkh* get_p2pkh (std::string& claim, std::string& signature);
};
std::ostream& operator<<(std::ostream &os, const snapshot &snap);
std::istream& operator>>(std::istream &is, snapshot &snap);
void prettyPrint (const snapshot &snap);
snapshot* makeTestSnapshot();

typedef std::shared_ptr<snapshot> snapshot_ptr;
typedef std::array<char,20> btc_address;
    
} } // btc::snapshot