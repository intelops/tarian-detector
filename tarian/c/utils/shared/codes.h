#ifndef __UTILS_SHARED_CODES_H__
#define __UTILS_SHARED_CODES_H__

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

#define TDC_SUCCESS 100
#define TDC_FAILURE 101

#define TDCE_RESERVE_SPACE 400
#define TDCE_NULL_POINTER 401
#define TDCE_MAP_SUBMIT 402
#define TDCE_UNKNOWN_TYPE 403
#define TDCE_UNDEFINED_INDEX 404
#define TDCE_write_CWD 405
#define TDCE_SCRATCH_SPACE_ALLOCATION 406

#endif