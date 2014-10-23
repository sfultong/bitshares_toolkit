/* 
 * File:   btc_create_snapshot.cpp
 * Author: sfultong
 *
 * Created on October 20, 2014, 6:54 PM
 */

#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <array>
#include <vector>
#include <iterator>
#include <fc/crypto/base58.hpp>

using namespace std;

#define HEADER_OFFSET 4 + 20 + 32 + 8 + 8

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
    
    snapshot_header (void): 
        version(1),
        total_claim_value(0),
        num_claims(0),
        p2pkh_offset(HEADER_OFFSET),
        p2sh_offset(HEADER_OFFSET),
        multisig_offset(HEADER_OFFSET),
        raw_script_offset(HEADER_OFFSET)
    {
        // test
        this->merkle_root[0] = 'a';
        this->merkle_root[1] = 'b';
        this->merkle_root[19] = 'z';
    }
};
std::ostream& operator<<(std::ostream &os, const snapshot_header &header) {
    os.write(reinterpret_cast<const char*>(&header.version), sizeof(uint32_t));
    std::copy(header.merkle_root.begin(), header.merkle_root.end(), std::ostream_iterator<char>(os));
    std::copy(header.block_hash.begin(), header.block_hash.end(), std::ostream_iterator<char>(os));
    os.write(reinterpret_cast<const char*>(&header.total_claim_value), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.num_claims), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.p2pkh_offset), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.p2sh_offset), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.multisig_offset), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.raw_script_offset), sizeof(uint64_t));
    return os;
}
std::istream& operator>>(std::istream &is, snapshot_header &header) {
    is.read(reinterpret_cast<char*>(&header.version), sizeof(uint32_t));
    //char buf[20 + 32];
    //is.read(buf, 20 + 32);
    // do these work? or do I have to try above approach?
    for (int i = 0; i < 20; i++) { 
        is >> header.merkle_root[i];
    }
    for (int i = 0; i < 32; i++) {
        is >> header.block_hash[i];
    }
    is.read(reinterpret_cast<char*>(&header.total_claim_value), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.num_claims), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.p2pkh_offset), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.p2sh_offset), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.multisig_offset), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.raw_script_offset), sizeof(uint64_t));
    return is;
}
void prettyPrint (const snapshot_header &header) {
    std::cout << "version\t" << header.version << "\n"
            << "merkle root\ttodo\n"
            << "block hash\ttodo\n"
            << "total claim value\t" << header.total_claim_value << "\n"
            << "number of claims\t" << header.num_claims << "\n"
            << "p2pkh offset\t" << header.p2pkh_offset << "\n"
            << "p2sh offset\t" << header.p2sh_offset << "\n"
            << "multisig offset\t" << header.multisig_offset << "\n"
            << "raw script offset\t" << header.raw_script_offset << "\n";
}

struct p2pkh {
    std::array<char,20> hash;
    uint64_t            amount;
    
    p2pkh (void) { }
    
    p2pkh (std::array<char,20> _hash, uint64_t _amount): 
        hash(_hash),
        amount(_amount)
    { }
    
    p2pkh (const p2pkh& other):
        hash(other.hash),
        amount(other.amount)
    { }
};
std::ostream& operator<<(std::ostream &os, const p2pkh &entry) {
    std::copy(entry.hash.begin(), entry.hash.end(), std::ostream_iterator<char>(os));
    os.write(reinterpret_cast<const char*>(&entry.amount), sizeof(uint64_t));
    return os;
}
std::istream& operator>>(std::istream &is, p2pkh &entry) {
    for (int i = 0; i < 20; i++) {
        is >> entry.hash[i];
    }
    is.read(reinterpret_cast<char*>(&entry.amount), sizeof(uint64_t));
    return is;        
}
void prettyPrint (const p2pkh &entry) {
    std::vector<char> vec;
    for (auto &c : entry.hash) {
        vec.push_back(c);
    }
    std::cout << fc::to_base58(vec) << "\t"
            << entry.amount << "\n";
}

struct snapshot {
    snapshot_header         header;
    std::vector<p2pkh>      p2pkh_entries;
    
    void add_p2pkh (p2pkh entry) {
        header.p2sh_offset += 28;
        header.multisig_offset += 28;
        header.raw_script_offset += 28;
        header.num_claims++;
        header.total_claim_value += entry.amount;
        p2pkh_entries.push_back(entry);
    }
};
std::ostream& operator<<(std::ostream &os, const snapshot &snap) {
    os << snap.header;
    for (auto &entry : snap.p2pkh_entries) {
        os << entry;
    }
    return os;
}
std::istream& operator>>(std::istream &is, snapshot &snap) {
    is >> snap.header;
    p2pkh entry;
    for (uint64_t i = HEADER_OFFSET; i < snap.header.p2sh_offset; i += 28) {
        is >> entry;
        snap.p2pkh_entries.push_back(p2pkh(entry));
    }
    return is;
}
void prettyPrint (const snapshot &snap) {
    prettyPrint(snap.header);
    std::cout << "-----p2pkh entries-----\n";
    for (auto &entry : snap.p2pkh_entries) {
        prettyPrint(entry);
    }
}

void writeTestSnapshot () {
    std::ofstream snapshot_bin("snapshot.bin", std::ofstream::binary);
    struct snapshot snapshot;
        
    std::array<char,20> hash;
    for (int i = 0; i < 20; i++) {
        hash[i] = 'a' + i;
    }
    snapshot.add_p2pkh(p2pkh(hash, 50));
    prettyPrint(snapshot);
    
    snapshot_bin << snapshot;
}

void loadAndPrint () {
    std::ifstream snapshot_bin("snapshot.bin", std::ifstream::binary);
    struct snapshot snapshot;
    
    snapshot_bin >> snapshot;
    prettyPrint(snapshot);
}

/*
 * 
 */
int main(int argc, char** argv) {
    if (2 == argc) {
        std::cout << "Writing snapshot\n";
        writeTestSnapshot();
    } else {
        std::cout << "Loading snapshot\n";
        loadAndPrint();
    }
    
    return 0;
}

