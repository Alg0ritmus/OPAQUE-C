# OPAQUE-MCU version (LITTLE-ENDIAN ONLY!!!)
This repo is a 'trimmed-down' version of our default OPAQUE implementation. It is optimized (memory optimization for MCU) on the client side. It is also suitable for utilizing ASM functions for GF arithmetic, which perform calculations over GF(2^P) and subsequently reduce the results back to GF(P) at appropriate locations in the ristretto255 code (see detailed descriptions in the default version). Server-side functions are removed
from the MCU version of OPAQUE because we believe that 
clients, being potentially low-performance devices, 
need optimization. In contrast, servers are typically 
more powerful, and they can run the default OPAQUE version from:
https://github.com/Alg0ritmus/OPAQUE-C

Basically, files that differ from the default version are those with the header version of 'version M.C.U x.x.x':
>  opaque.c  
   opaque.h  
   oprf.c  
   oprf.h  
   test.c  
   ristretto255/ristretto255.c  
   ristretto255/ristretto255.h

> ⚠️ **Important Note:**
These files are specific to the MCU version. For any updates to other files, please refer to the default version of our OPAQUE implementation. Just download the new default OPAQUE version and replace the desired files.

---
# Default (main) OPAQUE implementation

# Introduction
This repo is a part of my Master's thesis. This brach is dedicated
to optimized version of OPAQUE specifically for Client on MCU (Cortex M4).
Repository contains implemantation of OPAQUE (aPAKE) protocol.
NOTE that this implementation should be as closest to RFC
implementation as possible, so you should be able to follow
all this code with RFC specification and compare it line by line.
We're planning to write clean and comperhensive impl. of OPAQUE
protocol in C. We are also targetting on MCU platforms (Cortex M-4)
so a big part of our design is aimed on peformance, compactness and 
small size of impl. Also note that we decided (I decided,
but can be changed) that we are using D.1.2.1 configuration of OPAQUE.
D.1.2.1 configuration is specified in OPAQUE draft.
Offcial RFC used during implemenation creation:
https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-12.txt

In other words, we are implementing an elliptic curve solution based on Bernstein's elliptic curve c25519 with ristretto255 mapping.


Feel free to submit pull requests for any issues or questions you may have

# Pure C
We aimed to implement all underlying functions and logic in pure C without big libraries like libsodium etc. Therefore whole repo from finite field atirhmetic across ristretto255, sha512, OPRF protocol to OPAQUE is written here without using any library. We acctually extraced code snippets from libraries like CycloneCRYPTO, TeetNaCl etc.

# Big endian independance
We drew inspiration from [The byte order fallacy](https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html)and wrote our code with respect to endianness. The newest version of this repository (v1.0.0+) supports both little and big endian. This introduced a slight overhead (because we perform some corrections in places where they aren't needed when using little endian), but we find it worthwhile in terms of 'clean code.' This means that there is no need to perform any special conditional compilation for big-endian devices.

We also tested our implementation in the QEMU emulator on the Debian distro. A great introduction to testing big-endian implementations on Windows with QEMU is summarized by Stephan Brumme [here](https://create.stephan-brumme.com/big-endian/).

> NOTE: Endian-agnostic implementation is available only for `ristretto255/` NOT for whole OPAQUE protocol!

# Client/Server interface
We provide a Client/Server interface, eliminating the need for a deep understanding of the OPAQUE protocol to use our implementation. All functions required for proper Client-Server Authentication are available in `client_side.c` or `server_side.c`, respectively. While we have simplified the usage of our library, we have also created an `opaque_in_details` folder where the OPAQUE protocol is explained in detail, along with code examples based on this implementation.

# Optimization on Cortex-M4
During the creation of this library, our primary focus was on low-level optimization of ristretto255, which significantly enhances the entire OPAQUE protocol. We identified the most critical parts of our codebase, specifically finite-field arithmetic modulo P, and optimized them accordingly. In the first stage, we extracted arithmetic from libraries that best suited our purposes. In the second stage, we replaced them with an [ASM](https://github.com/Emill/X25519-Cortex-M4/blob/master/x25519-cortex-m4.h) implementation utilizing the modulo 2P method. This ASM implementation requires identifying crucial places in our code to reduce intermediate calculations correctly. Please note that manual replacement of the underlying finite field arithmetic is necessary to use it. If you are interested in the ristretto255 repository only, you can find it[ristretto255](https://github.com/Alg0ritmus/ristretto255_cyclone). There are multiple branches, and you can traverse them as needed, although not all of them may be updated.


# Makefile
There are three executables that can be built:<br>

*`test` -> runs OPAQUE tests
> `make test`

*`simulation` -> runs educational simulations (see opaque_in_details/)
> `make simulation`


> ⚠️ **Important Note:**
> 
> This library is intended for educational or experimental purposes only and is not suitable for production code. It may contain bugs, lack essential features, or be subject to frequent changes without backward compatibility. Using it in real projects is strongly discouraged.
>
> Please exercise caution and consider alternative, production-ready solutions for your application requirements.