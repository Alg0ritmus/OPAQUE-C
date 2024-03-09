# Ristretto255

This is a Ristretto255 implementation written purely in C, without any external libraries. However, we conducted research on existing cryptographic libraries and extracted the most suitable code snippets for our purposes, aiming for a lightweight, fast, memory-efficient, endian-agnostic implementation of Ristretto255.

Every function is described and contains a reference link to the original library from which it was extracted.

Our endian-agnostic implementation takes inputs in little-endian format and returns outputs in little-endian format. However, the calculations work correctly in the background on both little-endian and big-endian systems.

If you are on a big-endian device, you simply need to adjust inputs and outputs to/from the Ristretto functions. To learn more about our design, check the `ristretto.c` file.

---

# Usage

The `ristretto255/` folder contains everything you need to build OPAQUE in C, including modular arithmetic mod L. However, additional files such as `ristretto_main.c`, `xxhash.c`, `xxhash.h`, `test_config.h`, `py_modl_l_inverse.py`, and `Makefile` were added for testing our Ristretto implementation. If you do not intend to run these tests, feel free to delete these files as they are not necessary for application use (in this case, OPAQUE).

# How to run tests

run (on Win):
> 1) set `ifdef 1` in `ristretto_main.c` above `main()` function<br>
> 2) `make all`<br>
> 3) `./ristretto_main.exe`

clean
> 1) `make clean`