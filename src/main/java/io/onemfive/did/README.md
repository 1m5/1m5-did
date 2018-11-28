# Decentralized IDentification (DID) Service Implementation
There is one DID for each running 1M5 node. 
The DID is protected by a password hashed.
The DID can contain a network key for each network supported identifying this 1M5 node on the respective network.
Base networks supported by 1M5 are: IDM, I2P, Tor, and Clearnet. 
Clearnet is yet to be defined. 
IDM is yet to be designed.
Each network supported is identified as a Peer.
Zero or more personal identities can be managed by the DID through the Key Ring Service to provide content encryption/decryption and signatures.
Additional networks can be added as Peers as desired by applications building on 1M5.