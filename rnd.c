#include "rnd.h"

void rnd(uint8_t out[32],uint8_t seed){
  srand (seed);
  for (int i = 0; i < 32; ++i)
  {
    out[i] = rand()%0xFF;
  }
}