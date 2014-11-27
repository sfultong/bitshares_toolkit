

#include <btc/snapshot/snapshot.hpp>

#include <iostream>
#include <fstream>

using namespace btc::snapshot;


/*
 * 
 */
int main(int argc, char** argv) {
    if (2 == argc) {
        std::cout << "Writing snapshot\n";
        snapshot* snap = makeTestSnapshot();
        std::ofstream snapshot_bin("snapshot.bin", std::ofstream::binary);
        snapshot_bin << *snap;
        prettyPrint(*snap);

    } else {
        std::cout << "Loading snapshot\n";
        std::ifstream* snapshot_bin = new std::ifstream("snapshot.bin", std::ifstream::binary);
        snapshot snap(snapshot_bin);
        prettyPrint(snap);
        
        /*
         * TODO - 
         * 1. get a few bitcoin addresses, sign claims with them
         * 2. convert bitcoin addresses to 20 byte format used in snapshot
         * 3. create snapshot with 20 byte addresses
         * 4. verify get_p2pkh works for signed claims, verify it doesn't for addresses not in snapshot
         * 5. add claim transaction type to bts blockchain
         */
        
        std::string claim = "I claim some funds";
        std::string sig1 = "IERywusPqo2FludnjjhtubyytJBH35784JM6HsIL9R36Z7RzsmZtnAeYJjY8urkJuro2bDGSD0Ej1kT3OQaM3BA=";
        std::string sig2 = "H93YGdQHTeEagG7qBid5UesjQcJOtT9o15o0KwNBnqDOpH3J2z2QVRua0hY6o2r5khUFNHBbRK6iVKMlJaFgPB0=";
        std::string sig3 = "HxIfbCs4qBTwXjpZOWo7ipWFcBNx0qago32Fgi52pK/rmGwE3hC6WNdti4UfW/IvLwcfpQFtjU29hnPheDF0mMs=";
        p2pkh* claim1 = snap.get_p2pkh(claim, sig1);
        p2pkh* claim2 = snap.get_p2pkh(claim, sig2);
        p2pkh* claim3 = snap.get_p2pkh(claim, sig3);
        /*
        std::cout << "found amount:\t" << claim1->amount << "\n";
        std::cout << "found amount:\t" << claim2->amount << "\n";
        std::cout << "not found amount:\t" << snap.get_p2pkh(claim, sig3) << "\n"; 
         */ 
        
        /*
        snapshot* snap = new snapshot();
        snapshot_bin >> *snap;
        prettyPrint(*snap);
         */
        /*
        snapshot_header *header = new snapshot_header();
        snapshot_bin >> *header;
        prettyPrint(*header);
         */ 
    }
    
    return 0;
}

