#ifndef __UTILS_C_SHARED_ERROR_CODES_H__
#define __UTILS_C_SHARED_ERROR_CODES_H__

/* general status codes represented in format 1xx*/
enum general_codes_e {
  OK = 100UL, /* Task successfully completed */
  NOT_OK,
  NULL_POINTER_ERROR, 
  GEN_ERR_MAX = 199UL /* MAX LIMIT OF THIS CODE KIND*/
};

enum map_codes_e {
  RINGBUF_CAPACITY_REACHED_ERR = 200UL, /* ring buffer is at full capacity; no space available for new entries  */
  BUFFER_DATA_SIZE_EXCEEDED_ERR ,       /* data buffer capacity exceeded allocated threshold */
  BUFFER_FULL_ERR,
  ZERO_SIZE_ERR,
  MAP_ERROR_MAX = 299UL
};
#endif