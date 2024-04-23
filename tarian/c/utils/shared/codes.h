// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTILS_SHARED_CODES_H__
#define __UTILS_SHARED_CODES_H__

/**
 * @brief This code represents the success status
 *
 * `TDC_SUCCESS` is used to indicate that the operation was successful.
 */
#define TDC_SUCCESS 100

/**
 * @brief This code represents the failure status
 *
 * `TDC_FAILURE` is used to indicate that the operation was not successful.
 */
#define TDC_FAILURE 101

/**
 * @brief This code represents the status of a successful event filter out
 *        by the user defined filters in the kernel.
 *
 * `TDCE_FILTERED_OUT` is used to indicate that the event was successfully
 * dropped by the user defined filters and should not be sent to userspace.
 */
#define TDC_FILTERED_OUT 102

/**
 * @brief This code represents the status of a failed call to any function that
 *        tries to reserve space in an ebpf map or per cpu buffer
 *
 * `TDCE_MAP_SPACE_ALLOCATION` is used to indicate that space could not be
 * allocated in the ebpf maps or per cpu buffer.
 */
#define TDCE_MAP_SPACE_ALLOCATION 400

/**
 * @brief This code represents the status of a failed call to any function
 *        that receives a NULL pointer
 *
 * `TDCE_NULL_POINTER` is used to indicate that the caller passed a NULL pointer
 * to a function.
 */
#define TDCE_NULL_POINTER 401

/**
 * @brief This code represents the status of a failed call to
 *        `bpf_perf_event_output` or `bpf_ringbuf_output`.
 *
 * `TDCE_MAP_SUBMIT` is used to indicate that there was an error when trying to
 * submit data to an ebpf maps like perf event or ring buffer.
 */
#define TDCE_MAP_SUBMIT 402

/**
 * @brief This code represents the status of a failed call to any function
 *        that receives an unknown type
 *
 * `TDCE_UNKNOWN_TYPE` is used to indicate that the caller passed an unknown
 * type to a function. This could happen if the function is not updated to
 * handle a new type that was added to an enum for example.
 */
#define TDCE_UNKNOWN_TYPE 403

/**
 * @brief This code represents the status of a failed call to any function
 *        that receives an undefined index
 *
 * `TDCE_UNDEFINED_INDEX` is used to indicate that the caller passed an unknown
 * index to a function. This could happen if the function is not updated to
 * handle a new index that was added to an array for example.
 */
#define TDCE_UNDEFINED_INDEX 404

/**
 * @brief This code represents the status of a failed call to allocate scratch
 *        space in the kernel.
 *
 * `TDCE_SCRATCH_SPACE_ALLOCATION` is used to indicate that there was an error
 * when trying to allocate scratch space in the kernel.
 */
#define TDCE_SCRATCH_SPACE_ALLOCATION 405

#endif