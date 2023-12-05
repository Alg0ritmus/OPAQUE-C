#include "rnd.h"

void rnd(uint8_t out[32],int size){
  
  for (int i = 0; i < size; ++i)
  {
    out[i] = rand()%0xFF;
  }
}