/* THIS IS A SINGLE-FILE DISTRIBUTION CONCATENATED FROM THE OPEN62541 SOURCES
 * visit http://open62541.org/ for information about this software
 * Git-Revision: v0.3.0
 */

/*
 * Copyright (C) 2014-2018 the contributors as stated in the AUTHORS file
 *
 * This file is part of open62541. open62541 is free software: you can
 * redistribute it and/or modify it under the terms of the Mozilla Public
 * License v2.0 as stated in the LICENSE file provided with open62541.
 *
 * open62541 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE.
 */

#ifndef OPEN62541_H_
#define OPEN62541_H_

/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/build/src_generated/ua_config.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


#ifdef __cplusplus
extern "C" {
#endif

/**
 * open62541 Version
 * ----------------- */
#define UA_OPEN62541_VER_MAJOR 0
#define UA_OPEN62541_VER_MINOR 3
#define UA_OPEN62541_VER_PATCH 0
#define UA_OPEN62541_VER_LABEL "" /* Release candidate label, etc. */
#define UA_OPEN62541_VER_COMMIT "v0.3.0"

/**
 * Feature Options
 * ---------------
 * Changing the feature options has no effect on a pre-compiled library. */
#define UA_LOGLEVEL 300
#define UA_ENABLE_METHODCALLS
#define UA_ENABLE_NODEMANAGEMENT
#define UA_ENABLE_SUBSCRIPTIONS
/* #undef UA_ENABLE_MULTITHREADING */
/* #undef UA_ENABLE_ENCRYPTION */

/* Advanced Options */
#define UA_ENABLE_STATUSCODE_DESCRIPTIONS
#define UA_ENABLE_TYPENAMES
/* #undef UA_ENABLE_DETERMINISTIC_RNG */
/* #undef UA_ENABLE_NONSTANDARD_UDP */
#define UA_ENABLE_DISCOVERY
/* #undef UA_ENABLE_DISCOVERY_MULTICAST */
#define UA_ENABLE_DISCOVERY_SEMAPHORE
/* #undef UA_ENABLE_UNIT_TEST_FAILURE_HOOKS */
/* #undef UA_ENABLE_VALGRIND_INTERACTIVE */
#define UA_VALGRIND_INTERACTIVE_INTERVAL 1000

/* Options for Debugging */
/* #undef UA_DEBUG */
/* #undef UA_DEBUG_DUMP_PKGS */

/**
 * C99 Definitions
 * --------------- */
#include <string.h>
#include <stddef.h>

/* Include stdint.h and stdbool.h or workaround for older Visual Studios */
#if !defined(_MSC_VER) || _MSC_VER >= 1600
# include <stdint.h>
# include <stdbool.h> /* C99 Boolean */
# if defined(_WRS_KERNEL)
# define UINT32_C(x) ((x) + (UINT32_MAX - UINT32_MAX)) 
# endif
#else
# if !defined(__bool_true_false_are_defined)
#  define bool short
#  define true 1
#  define false 0
#  define __bool_true_false_are_defined
# endif
#endif

/**
 * Assertions
 * ----------
 * The assert macro is disabled by defining NDEBUG. It is often forgotten to
 * include -DNDEBUG in the compiler flags when using the single-file release. So
 * we make assertions dependent on the UA_DEBUG definition handled by CMake. */
#ifdef UA_DEBUG
# include <assert.h>
# define UA_assert(ignore) assert(ignore)
#else
# define UA_assert(ignore)
#endif

/* Outputs an error message at compile time if the assert fails.
 * Example usage:
 * UA_STATIC_ASSERT(sizeof(long)==7, use_another_compiler_luke)
 * See: https://stackoverflow.com/a/4815532/869402 */
#if defined(__cplusplus) && __cplusplus >= 201103L /* C++11 or above */
# define UA_STATIC_ASSERT(cond,msg) static_assert(cond, #msg)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L /* C11 or above */
# define UA_STATIC_ASSERT(cond,msg) _Static_assert(cond, #msg)
#elif defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER) /* GCC, Clang, MSC */
# define UA_CTASTR2(pre,post) pre ## post
# define UA_CTASTR(pre,post) UA_CTASTR2(pre,post)
# ifndef __COUNTER__ /* PPC GCC fix */
#  define __COUNTER__ __LINE__
# endif
# define UA_STATIC_ASSERT(cond,msg)                             \
    typedef struct {                                            \
        int UA_CTASTR(static_assertion_failed_,msg) : !!(cond); \
    } UA_CTASTR(static_assertion_failed_,__COUNTER__)
#else /* Everybody else */
# define UA_STATIC_ASSERT(cond,msg) typedef char static_assertion_##msg[(cond)?1:-1]
#endif

/**
 * Memory Management
 * -----------------
 * The default is to use the malloc implementation from ``stdlib.h``. Override
 * if required. Changing the settings has no effect on a pre-compiled
 * library. */
#include <stdlib.h>
#if defined(_WIN32) && !defined(__clang__)
# include <malloc.h>
#endif

#if !defined(UA_FREERTOS)

# define UA_free(ptr) free(ptr)
# define UA_malloc(size) malloc(size)
# define UA_calloc(num, size) calloc(num, size)
# define UA_realloc(ptr, size) realloc(ptr, size)

#else

# include <FreeRTOS.h>

# define UA_free(ptr) vPortFree(ptr)
# define UA_malloc(size) pvPortMalloc(size)
# define UA_calloc(num, size) pvPortCalloc(num, size)
# define UA_realloc(ptr, size) pvPortRealloc(ptr, size)

#endif

/* Stack-allocation of memory. Use C99 variable-length arrays if possible.
 * Otherwise revert to alloca. Note that alloca is not supported on some
 * plattforms. */
#if defined(__GNUC__) || defined(__clang__)
# define UA_STACKARRAY(TYPE, NAME, SIZE) TYPE NAME[SIZE]
#elif defined(_WIN32)
# define UA_STACKARRAY(TYPE, NAME, SIZE) \
    TYPE *NAME = (TYPE*)_alloca(sizeof(TYPE) * SIZE)
#else
# include <alloca.h>
# define UA_STACKARRAY(TYPE, NAME, SIZE) \
    TYPE *NAME = (TYPE*)alloca(sizeof(TYPE) * SIZE)
#endif

/**
 * Function Export
 * ---------------
 * On Win32: Define ``UA_DYNAMIC_LINKING`` and ``UA_DYNAMIC_LINKING_EXPORT`` in
 * order to export symbols for a DLL. Define ``UA_DYNAMIC_LINKING`` only to
 * import symbols from a DLL.*/
/* #undef UA_DYNAMIC_LINKING */

#if defined(_WIN32) && defined(UA_DYNAMIC_LINKING)
# ifdef UA_DYNAMIC_LINKING_EXPORT /* export dll */
#  ifdef __GNUC__
#   define UA_EXPORT __attribute__ ((dllexport))
#  else
#   define UA_EXPORT __declspec(dllexport)
#  endif
# else /* import dll */
#  ifdef __GNUC__
#   define UA_EXPORT __attribute__ ((dllimport))
#  else
#   define UA_EXPORT __declspec(dllimport)
#  endif
# endif
#else /* non win32 */
# if __GNUC__ || __clang__
#  define UA_EXPORT __attribute__ ((visibility ("default")))
# endif
#endif
#ifndef UA_EXPORT
# define UA_EXPORT /* fallback to default */
#endif

/**
 * Inline Functions
 * ---------------- */
#ifdef _MSC_VER
# define UA_INLINE __inline
#else
# define UA_INLINE inline
#endif

/**
 * Non-aliasing pointers
 * -------------------- */
#ifdef _MSC_VER
# define UA_RESTRICT __restrict
#elif defined(__GNUC__)
# define UA_RESTRICT __restrict__
#else
# define UA_RESTRICT restrict
#endif

/**
 * Function attributes
 * ------------------- */
#if defined(__GNUC__) || defined(__clang__)
# define UA_FUNC_ATTR_MALLOC __attribute__((malloc))
# define UA_FUNC_ATTR_PURE __attribute__ ((pure))
# define UA_FUNC_ATTR_CONST __attribute__((const))
# define UA_FUNC_ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
# define UA_FORMAT(X,Y) __attribute__ ((format (printf, X, Y)))
#else
# define UA_FUNC_ATTR_MALLOC
# define UA_FUNC_ATTR_PURE
# define UA_FUNC_ATTR_CONST
# define UA_FUNC_ATTR_WARN_UNUSED_RESULT
# define UA_FORMAT(X,Y)
#endif

#if defined(__GNUC__) || defined(__clang__)
# define UA_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
# define UA_DEPRECATED __declspec(deprecated)
#else
# define UA_DEPRECATED
#endif

/**
 * Detect Binary Overlaying for Encoding
 * -------------------------------------
 * Integers and floating point numbers are transmitted in little-endian (IEEE 754
 * for floating point) encoding. If the target architecture uses the same
 * format, numeral datatypes can be memcpy'd (overlayed) on the binary stream.
 * This speeds up encoding.
 *
 * Integer Endianness
 * ^^^^^^^^^^^^^^^^^^
 * The definition ``UA_BINARY_OVERLAYABLE_INTEGER`` is true when the integer
 * representation of the target architecture is little-endian. */
#if defined(_WIN32)
# define UA_BINARY_OVERLAYABLE_INTEGER 1
#elif (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
      (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
# define UA_BINARY_OVERLAYABLE_INTEGER 1
#elif defined(__linux__) /* Linux (including Android) */
# include <endian.h>
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define UA_BINARY_OVERLAYABLE_INTEGER 1
# endif
#elif defined(__OpenBSD__) /* OpenBSD */
# include <sys/endian.h>
# if BYTE_ORDER == LITTLE_ENDIAN
#  define UA_BINARY_OVERLAYABLE_INTEGER 1
# endif
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__) /* Other BSD */
# include <sys/endian.h>
# if _BYTE_ORDER == _LITTLE_ENDIAN
#  define UA_BINARY_OVERLAYABLE_INTEGER 1
# endif
#elif defined(__APPLE__) /* Apple (MacOS, iOS) */
# include <libkern/OSByteOrder.h>
# if defined(__LITTLE_ENDIAN__)
#  define UA_BINARY_OVERLAYABLE_INTEGER 1
# endif
#elif defined(__QNX__) || defined(__QNXNTO__) /* QNX */
# include <gulliver.h>
# if defined(__LITTLEENDIAN__)
#  define UA_BINARY_OVERLAYABLE_INTEGER 1
# endif
#endif

#ifndef UA_BINARY_OVERLAYABLE_INTEGER
# define UA_BINARY_OVERLAYABLE_INTEGER 0
#endif

/**
 * Float Endianness
 * ^^^^^^^^^^^^^^^^
 * The definition ``UA_BINARY_OVERLAYABLE_FLOAT`` is true when the floating
 * point number representation of the target architecture is IEEE 754. Note that
 * this cannot be reliable detected with macros for the clang compiler
 * (beginning of 2017). ``UA_BINARY_OVERLAYABLE_FLOAT`` can be manually set if
 * the target is known to be little endian with floats in the IEEE 754
 * format. */

#if defined(_WIN32)
# define UA_BINARY_OVERLAYABLE_FLOAT 1
#elif defined(__FLOAT_WORD_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    (__FLOAT_WORD_ORDER__ == __ORDER_LITTLE_ENDIAN__) /* Defined only in GCC */
# define UA_BINARY_OVERLAYABLE_FLOAT 1
#elif defined(__FLOAT_WORD_ORDER) && defined(__LITTLE_ENDIAN) && \
    (__FLOAT_WORD_ORDER == __LITTLE_ENDIAN) /* Defined only in GCC */
# define UA_BINARY_OVERLAYABLE_FLOAT 1
#elif defined(__linux__) /* Linux (including Android) */
# include <endian.h>
# if defined(__ANDROID__)
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define UA_BINARY_OVERLAYABLE_INTEGER 1
#  endif
# elif __FLOAT_WORD_ORDER == __LITTLE_ENDIAN
#  define UA_BINARY_OVERLAYABLE_FLOAT 1
# endif
#elif defined(_WRS_KERNEL)
# define UA_BINARY_OVERLAYABLE_FLOAT 1
#endif

#ifndef UA_BINARY_OVERLAYABLE_FLOAT
# define UA_BINARY_OVERLAYABLE_FLOAT 0
#endif

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/deps/ms_stdint.h" ***********************************/

// ISO C9x  compliant stdint.h for Microsoft Visual Studio
// Based on ISO/IEC 9899:TC2 Committee draft (May 6, 2005) WG14/N1124 
// 
//  Copyright (c) 2006-2013 Alexander Chemeris
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 
//   1. Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
// 
//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
// 
//   3. Neither the name of the product nor the names of its contributors may
//      be used to endorse or promote products derived from this software
//      without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
///////////////////////////////////////////////////////////////////////////////

#if !defined(_MSC_VER) || _MSC_VER >= 1600 // [
#include <stdint.h>
#else


#if _MSC_VER > 1000
#pragma once
#endif

#include <limits.h>

// For Visual Studio 6 in C++ mode and for many Visual Studio versions when
// compiling for ARM we should wrap <wchar.h> include with 'extern "C++" {}'
// or compiler give many errors like this:
//   error C2733: second C linkage of overloaded function 'wmemchr' not allowed
#ifndef UNDER_CE
#ifdef __cplusplus
extern "C" {
#endif
#  include <wchar.h>
#ifdef __cplusplus
}
#endif
#endif

// Define _W64 macros to mark types changing their size, like intptr_t.
#ifndef _W64
#  if !defined(__midl) && (defined(_X86_) || defined(_M_IX86)) && _MSC_VER >= 1300
#     define _W64 __w64
#  else
#     define _W64
#  endif
#endif


// 7.18.1 Integer types

// 7.18.1.1 Exact-width integer types

// Visual Studio 6 and Embedded Visual C++ 4 doesn't
// realize that, e.g. char has the same size as __int8
// so we give up on __intX for them.
#if (_MSC_VER < 1300)
   typedef signed char       int8_t;
   typedef signed short      int16_t;
   typedef signed int        int32_t;
   typedef unsigned char     uint8_t;
   typedef unsigned short    uint16_t;
   typedef unsigned int      uint32_t;
#else
   typedef signed __int8     int8_t;
   typedef signed __int16    int16_t;
   typedef signed __int32    int32_t;
   typedef unsigned __int8   uint8_t;
   typedef unsigned __int16  uint16_t;
   typedef unsigned __int32  uint32_t;
#endif
typedef signed __int64       int64_t;
typedef unsigned __int64     uint64_t;


// 7.18.1.2 Minimum-width integer types
typedef int8_t    int_least8_t;
typedef int16_t   int_least16_t;
typedef int32_t   int_least32_t;
typedef int64_t   int_least64_t;
typedef uint8_t   uint_least8_t;
typedef uint16_t  uint_least16_t;
typedef uint32_t  uint_least32_t;
typedef uint64_t  uint_least64_t;

// 7.18.1.3 Fastest minimum-width integer types
typedef int8_t    int_fast8_t;
typedef int16_t   int_fast16_t;
typedef int32_t   int_fast32_t;
typedef int64_t   int_fast64_t;
typedef uint8_t   uint_fast8_t;
typedef uint16_t  uint_fast16_t;
typedef uint32_t  uint_fast32_t;
typedef uint64_t  uint_fast64_t;

// 7.18.1.4 Integer types capable of holding object pointers
#ifdef _WIN64 // [
   typedef signed __int64    intptr_t;
   typedef unsigned __int64  uintptr_t;
#else // _WIN64 ][
   typedef _W64 signed int   intptr_t;
   typedef _W64 unsigned int uintptr_t;
#endif // _WIN64 ]

// 7.18.1.5 Greatest-width integer types
typedef int64_t   intmax_t;
typedef uint64_t  uintmax_t;


// 7.18.2 Limits of specified-width integer types

#if !defined(__cplusplus) || defined(__STDC_LIMIT_MACROS) // [   See footnote 220 at page 257 and footnote 221 at page 259

// 7.18.2.1 Limits of exact-width integer types
#define INT8_MIN     ((int8_t)_I8_MIN)
#define INT8_MAX     _I8_MAX
#define INT16_MIN    ((int16_t)_I16_MIN)
#define INT16_MAX    _I16_MAX
#define INT32_MIN    ((int32_t)_I32_MIN)
#define INT32_MAX    _I32_MAX
#define INT64_MIN    ((int64_t)_I64_MIN)
#define INT64_MAX    _I64_MAX
#define UINT8_MAX    _UI8_MAX
#define UINT16_MAX   _UI16_MAX
#define UINT32_MAX   _UI32_MAX
#define UINT64_MAX   _UI64_MAX

// 7.18.2.2 Limits of minimum-width integer types
#define INT_LEAST8_MIN    INT8_MIN
#define INT_LEAST8_MAX    INT8_MAX
#define INT_LEAST16_MIN   INT16_MIN
#define INT_LEAST16_MAX   INT16_MAX
#define INT_LEAST32_MIN   INT32_MIN
#define INT_LEAST32_MAX   INT32_MAX
#define INT_LEAST64_MIN   INT64_MIN
#define INT_LEAST64_MAX   INT64_MAX
#define UINT_LEAST8_MAX   UINT8_MAX
#define UINT_LEAST16_MAX  UINT16_MAX
#define UINT_LEAST32_MAX  UINT32_MAX
#define UINT_LEAST64_MAX  UINT64_MAX

// 7.18.2.3 Limits of fastest minimum-width integer types
#define INT_FAST8_MIN    INT8_MIN
#define INT_FAST8_MAX    INT8_MAX
#define INT_FAST16_MIN   INT16_MIN
#define INT_FAST16_MAX   INT16_MAX
#define INT_FAST32_MIN   INT32_MIN
#define INT_FAST32_MAX   INT32_MAX
#define INT_FAST64_MIN   INT64_MIN
#define INT_FAST64_MAX   INT64_MAX
#define UINT_FAST8_MAX   UINT8_MAX
#define UINT_FAST16_MAX  UINT16_MAX
#define UINT_FAST32_MAX  UINT32_MAX
#define UINT_FAST64_MAX  UINT64_MAX

// 7.18.2.4 Limits of integer types capable of holding object pointers
#ifdef _WIN64 // [
#  define INTPTR_MIN   INT64_MIN
#  define INTPTR_MAX   INT64_MAX
#  define UINTPTR_MAX  UINT64_MAX
#else // _WIN64 ][
#  define INTPTR_MIN   INT32_MIN
#  define INTPTR_MAX   INT32_MAX
#  define UINTPTR_MAX  UINT32_MAX
#endif // _WIN64 ]

// 7.18.2.5 Limits of greatest-width integer types
#define INTMAX_MIN   INT64_MIN
#define INTMAX_MAX   INT64_MAX
#define UINTMAX_MAX  UINT64_MAX

// 7.18.3 Limits of other integer types

#ifdef _WIN64 // [
#  define PTRDIFF_MIN  _I64_MIN
#  define PTRDIFF_MAX  _I64_MAX
#else  // _WIN64 ][
#  define PTRDIFF_MIN  _I32_MIN
#  define PTRDIFF_MAX  _I32_MAX
#endif  // _WIN64 ]

#define SIG_ATOMIC_MIN  INT_MIN
#define SIG_ATOMIC_MAX  INT_MAX

#ifndef SIZE_MAX // [
#  ifdef _WIN64 // [
#     define SIZE_MAX  _UI64_MAX
#  else // _WIN64 ][
#     define SIZE_MAX  _UI32_MAX
#  endif // _WIN64 ]
#endif // SIZE_MAX ]

// WCHAR_MIN and WCHAR_MAX are also defined in <wchar.h>
#ifndef WCHAR_MIN // [
#  define WCHAR_MIN  0
#endif  // WCHAR_MIN ]
#ifndef WCHAR_MAX // [
#  define WCHAR_MAX  _UI16_MAX
#endif  // WCHAR_MAX ]

#define WINT_MIN  0
#define WINT_MAX  _UI16_MAX

#endif // __STDC_LIMIT_MACROS ]


// 7.18.4 Limits of other integer types

#if !defined(__cplusplus) || defined(__STDC_CONSTANT_MACROS) // [   See footnote 224 at page 260

// 7.18.4.1 Macros for minimum-width integer constants

#define INT8_C(val)  val##i8
#define INT16_C(val) val##i16
#define INT32_C(val) val##i32
#define INT64_C(val) val##i64

#define UINT8_C(val)  val##ui8
#define UINT16_C(val) val##ui16
#define UINT32_C(val) val##ui32
#define UINT64_C(val) val##ui64

// 7.18.4.2 Macros for greatest-width integer constants
// These #ifndef's are needed to prevent collisions with <boost/cstdint.hpp>.
// Check out Issue 9 for the details.
#ifndef INTMAX_C //   [
#  define INTMAX_C   INT64_C
#endif // INTMAX_C    ]
#ifndef UINTMAX_C //  [
#  define UINTMAX_C  UINT64_C
#endif // UINTMAX_C   ]

#endif // __STDC_CONSTANT_MACROS ]


#endif // !defined(_MSC_VER) || _MSC_VER >= 1600 ]

/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_constants.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2016-2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2016 (c) Sten Grüner
 *    Copyright 2016-2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Florian Palm
 */


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Standard-Defined Constants
 * ==========================
 * This section contains numerical and string constants that are defined in the
 * OPC UA standard.
 *
 * .. _attribute-id:
 *
 * Attribute Id
 * ------------
 * Every node in an OPC UA information model contains attributes depending on
 * the node type. Possible attributes are as follows: */

typedef enum {
    UA_ATTRIBUTEID_NODEID                  = 1,
    UA_ATTRIBUTEID_NODECLASS               = 2,
    UA_ATTRIBUTEID_BROWSENAME              = 3,
    UA_ATTRIBUTEID_DISPLAYNAME             = 4,
    UA_ATTRIBUTEID_DESCRIPTION             = 5,
    UA_ATTRIBUTEID_WRITEMASK               = 6,
    UA_ATTRIBUTEID_USERWRITEMASK           = 7,
    UA_ATTRIBUTEID_ISABSTRACT              = 8,
    UA_ATTRIBUTEID_SYMMETRIC               = 9,
    UA_ATTRIBUTEID_INVERSENAME             = 10,
    UA_ATTRIBUTEID_CONTAINSNOLOOPS         = 11,
    UA_ATTRIBUTEID_EVENTNOTIFIER           = 12,
    UA_ATTRIBUTEID_VALUE                   = 13,
    UA_ATTRIBUTEID_DATATYPE                = 14,
    UA_ATTRIBUTEID_VALUERANK               = 15,
    UA_ATTRIBUTEID_ARRAYDIMENSIONS         = 16,
    UA_ATTRIBUTEID_ACCESSLEVEL             = 17,
    UA_ATTRIBUTEID_USERACCESSLEVEL         = 18,
    UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL = 19,
    UA_ATTRIBUTEID_HISTORIZING             = 20,
    UA_ATTRIBUTEID_EXECUTABLE              = 21,
    UA_ATTRIBUTEID_USEREXECUTABLE          = 22
} UA_AttributeId;

/**
 * Access Level Masks
 * ------------------
 * The access level to a node is given by the following constants that are ANDed
 * with the overall access level. */

#define UA_ACCESSLEVELMASK_READ           (0x01<<0)
#define UA_ACCESSLEVELMASK_WRITE          (0x01<<1)
#define UA_ACCESSLEVELMASK_HISTORYREAD    (0x01<<2)
#define UA_ACCESSLEVELMASK_HISTORYWRITE   (0x01<<3)
#define UA_ACCESSLEVELMASK_SEMANTICCHANGE (0x01<<4)
#define UA_ACCESSLEVELMASK_STATUSWRITE    (0x01<<5)
#define UA_ACCESSLEVELMASK_TIMESTAMPWRITE (0x01<<6)

/**
 * Write Masks
 * -----------
 * The write mask and user write mask is given by the following constants that
 * are ANDed for the overall write mask. Part 3: 5.2.7 Table 2 */

#define UA_WRITEMASK_ACCESSLEVEL             (0x01<<0)
#define UA_WRITEMASK_ARRRAYDIMENSIONS        (0x01<<1)
#define UA_WRITEMASK_BROWSENAME              (0x01<<2)
#define UA_WRITEMASK_CONTAINSNOLOOPS         (0x01<<3)
#define UA_WRITEMASK_DATATYPE                (0x01<<4)
#define UA_WRITEMASK_DESCRIPTION             (0x01<<5)
#define UA_WRITEMASK_DISPLAYNAME             (0x01<<6)
#define UA_WRITEMASK_EVENTNOTIFIER           (0x01<<7)
#define UA_WRITEMASK_EXECUTABLE              (0x01<<8)
#define UA_WRITEMASK_HISTORIZING             (0x01<<9)
#define UA_WRITEMASK_INVERSENAME             (0x01<<10)
#define UA_WRITEMASK_ISABSTRACT              (0x01<<11)
#define UA_WRITEMASK_MINIMUMSAMPLINGINTERVAL (0x01<<12)
#define UA_WRITEMASK_NODECLASS               (0x01<<13)
#define UA_WRITEMASK_NODEID                  (0x01<<14)
#define UA_WRITEMASK_SYMMETRIC               (0x01<<15)
#define UA_WRITEMASK_USERACCESSLEVEL         (0x01<<16)
#define UA_WRITEMASK_USEREXECUTABLE          (0x01<<17)
#define UA_WRITEMASK_USERWRITEMASK           (0x01<<18)
#define UA_WRITEMASK_VALUERANK               (0x01<<19)
#define UA_WRITEMASK_WRITEMASK               (0x01<<20)
#define UA_WRITEMASK_VALUEFORVARIABLETYPE    (0x01<<21)

/**
 * .. _statuscodes:
 *
 * StatusCodes
 * -----------
 * StatusCodes are extensively used in the OPC UA protocol and in the open62541
 * API. They are represented by the :ref:`statuscode` data type. The following
 * definitions are autogenerated from the ``Opc.Ua.StatusCodes.csv`` file provided
 * with the OPC UA standard. */

#define UA_STATUSCODE_GOOD 0x00
#define UA_STATUSCODE_BADUNEXPECTEDERROR 0x80010000 // An unexpected error occurred.
#define UA_STATUSCODE_BADINTERNALERROR 0x80020000 // An internal error occurred as a result of a programming or configuration error.
#define UA_STATUSCODE_BADOUTOFMEMORY 0x80030000 // Not enough memory to complete the operation.
#define UA_STATUSCODE_BADRESOURCEUNAVAILABLE 0x80040000 // An operating system resource is not available.
#define UA_STATUSCODE_BADCOMMUNICATIONERROR 0x80050000 // A low level communication error occurred.
#define UA_STATUSCODE_BADENCODINGERROR 0x80060000 // Encoding halted because of invalid data in the objects being serialized.
#define UA_STATUSCODE_BADDECODINGERROR 0x80070000 // Decoding halted because of invalid data in the stream.
#define UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED 0x80080000 // The message encoding/decoding limits imposed by the stack have been exceeded.
#define UA_STATUSCODE_BADREQUESTTOOLARGE 0x80b80000 // The request message size exceeds limits set by the server.
#define UA_STATUSCODE_BADRESPONSETOOLARGE 0x80b90000 // The response message size exceeds limits set by the client.
#define UA_STATUSCODE_BADUNKNOWNRESPONSE 0x80090000 // An unrecognized response was received from the server.
#define UA_STATUSCODE_BADTIMEOUT 0x800a0000 // The operation timed out.
#define UA_STATUSCODE_BADSERVICEUNSUPPORTED 0x800b0000 // The server does not support the requested service.
#define UA_STATUSCODE_BADSHUTDOWN 0x800c0000 // The operation was cancelled because the application is shutting down.
#define UA_STATUSCODE_BADSERVERNOTCONNECTED 0x800d0000 // The operation could not complete because the client is not connected to the server.
#define UA_STATUSCODE_BADSERVERHALTED 0x800e0000 // The server has stopped and cannot process any requests.
#define UA_STATUSCODE_BADNOTHINGTODO 0x800f0000 // There was nothing to do because the client passed a list of operations with no elements.
#define UA_STATUSCODE_BADTOOMANYOPERATIONS 0x80100000 // The request could not be processed because it specified too many operations.
#define UA_STATUSCODE_BADTOOMANYMONITOREDITEMS 0x80db0000 // The request could not be processed because there are too many monitored items in the subscription.
#define UA_STATUSCODE_BADDATATYPEIDUNKNOWN 0x80110000 // The extension object cannot be (de)serialized because the data type id is not recognized.
#define UA_STATUSCODE_BADCERTIFICATEINVALID 0x80120000 // The certificate provided as a parameter is not valid.
#define UA_STATUSCODE_BADSECURITYCHECKSFAILED 0x80130000 // An error occurred verifying security.
#define UA_STATUSCODE_BADCERTIFICATETIMEINVALID 0x80140000 // The Certificate has expired or is not yet valid.
#define UA_STATUSCODE_BADCERTIFICATEISSUERTIMEINVALID 0x80150000 // An Issuer Certificate has expired or is not yet valid.
#define UA_STATUSCODE_BADCERTIFICATEHOSTNAMEINVALID 0x80160000 // The HostName used to connect to a Server does not match a HostName in the Certificate.
#define UA_STATUSCODE_BADCERTIFICATEURIINVALID 0x80170000 // The URI specified in the ApplicationDescription does not match the URI in the Certificate.
#define UA_STATUSCODE_BADCERTIFICATEUSENOTALLOWED 0x80180000 // The Certificate may not be used for the requested operation.
#define UA_STATUSCODE_BADCERTIFICATEISSUERUSENOTALLOWED 0x80190000 // The Issuer Certificate may not be used for the requested operation.
#define UA_STATUSCODE_BADCERTIFICATEUNTRUSTED 0x801a0000 // The Certificate is not trusted.
#define UA_STATUSCODE_BADCERTIFICATEREVOCATIONUNKNOWN 0x801b0000 // It was not possible to determine if the Certificate has been revoked.
#define UA_STATUSCODE_BADCERTIFICATEISSUERREVOCATIONUNKNOWN 0x801c0000 // It was not possible to determine if the Issuer Certificate has been revoked.
#define UA_STATUSCODE_BADCERTIFICATEREVOKED 0x801d0000 // The certificate has been revoked.
#define UA_STATUSCODE_BADCERTIFICATEISSUERREVOKED 0x801e0000 // The issuer certificate has been revoked.
#define UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE 0x810d0000 // The certificate chain is incomplete.
#define UA_STATUSCODE_BADUSERACCESSDENIED 0x801f0000 // User does not have permission to perform the requested operation.
#define UA_STATUSCODE_BADIDENTITYTOKENINVALID 0x80200000 // The user identity token is not valid.
#define UA_STATUSCODE_BADIDENTITYTOKENREJECTED 0x80210000 // The user identity token is valid but the server has rejected it.
#define UA_STATUSCODE_BADSECURECHANNELIDINVALID 0x80220000 // The specified secure channel is no longer valid.
#define UA_STATUSCODE_BADINVALIDTIMESTAMP 0x80230000 // The timestamp is outside the range allowed by the server.
#define UA_STATUSCODE_BADNONCEINVALID 0x80240000 // The nonce does appear to be not a random value or it is not the correct length.
#define UA_STATUSCODE_BADSESSIONIDINVALID 0x80250000 // The session id is not valid.
#define UA_STATUSCODE_BADSESSIONCLOSED 0x80260000 // The session was closed by the client.
#define UA_STATUSCODE_BADSESSIONNOTACTIVATED 0x80270000 // The session cannot be used because ActivateSession has not been called.
#define UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID 0x80280000 // The subscription id is not valid.
#define UA_STATUSCODE_BADREQUESTHEADERINVALID 0x802a0000 // The header for the request is missing or invalid.
#define UA_STATUSCODE_BADTIMESTAMPSTORETURNINVALID 0x802b0000 // The timestamps to return parameter is invalid.
#define UA_STATUSCODE_BADREQUESTCANCELLEDBYCLIENT 0x802c0000 // The request was cancelled by the client.
#define UA_STATUSCODE_BADTOOMANYARGUMENTS 0x80e50000 // Too many arguments were provided.
#define UA_STATUSCODE_BADLICENSEEXPIRED 0x810E0000 // The server requires a license to operate in general or to perform a service or operation, but existing license is expired.
#define UA_STATUSCODE_BADLICENSELIMITSEXCEEDED 0x810F0000 // The server has limits on number of allowed operations / objects, based on installed licenses, and these limits where exceeded.
#define UA_STATUSCODE_BADLICENSENOTAVAILABLE 0x81100000 // The server does not have a license which is required to operate in general or to perform a service or operation.
#define UA_STATUSCODE_GOODSUBSCRIPTIONTRANSFERRED 0x002d0000 // The subscription was transferred to another session.
#define UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY 0x002e0000 // The processing will complete asynchronously.
#define UA_STATUSCODE_GOODOVERLOAD 0x002f0000 // Sampling has slowed down due to resource limitations.
#define UA_STATUSCODE_GOODCLAMPED 0x00300000 // The value written was accepted but was clamped.
#define UA_STATUSCODE_BADNOCOMMUNICATION 0x80310000 // Communication with the data source is defined, but not established, and there is no last known value available.
#define UA_STATUSCODE_BADWAITINGFORINITIALDATA 0x80320000 // Waiting for the server to obtain values from the underlying data source.
#define UA_STATUSCODE_BADNODEIDINVALID 0x80330000 // The syntax of the node id is not valid.
#define UA_STATUSCODE_BADNODEIDUNKNOWN 0x80340000 // The node id refers to a node that does not exist in the server address space.
#define UA_STATUSCODE_BADATTRIBUTEIDINVALID 0x80350000 // The attribute is not supported for the specified Node.
#define UA_STATUSCODE_BADINDEXRANGEINVALID 0x80360000 // The syntax of the index range parameter is invalid.
#define UA_STATUSCODE_BADINDEXRANGENODATA 0x80370000 // No data exists within the range of indexes specified.
#define UA_STATUSCODE_BADDATAENCODINGINVALID 0x80380000 // The data encoding is invalid.
#define UA_STATUSCODE_BADDATAENCODINGUNSUPPORTED 0x80390000 // The server does not support the requested data encoding for the node.
#define UA_STATUSCODE_BADNOTREADABLE 0x803a0000 // The access level does not allow reading or subscribing to the Node.
#define UA_STATUSCODE_BADNOTWRITABLE 0x803b0000 // The access level does not allow writing to the Node.
#define UA_STATUSCODE_BADOUTOFRANGE 0x803c0000 // The value was out of range.
#define UA_STATUSCODE_BADNOTSUPPORTED 0x803d0000 // The requested operation is not supported.
#define UA_STATUSCODE_BADNOTFOUND 0x803e0000 // A requested item was not found or a search operation ended without success.
#define UA_STATUSCODE_BADOBJECTDELETED 0x803f0000 // The object cannot be used because it has been deleted.
#define UA_STATUSCODE_BADNOTIMPLEMENTED 0x80400000 // Requested operation is not implemented.
#define UA_STATUSCODE_BADMONITORINGMODEINVALID 0x80410000 // The monitoring mode is invalid.
#define UA_STATUSCODE_BADMONITOREDITEMIDINVALID 0x80420000 // The monitoring item id does not refer to a valid monitored item.
#define UA_STATUSCODE_BADMONITOREDITEMFILTERINVALID 0x80430000 // The monitored item filter parameter is not valid.
#define UA_STATUSCODE_BADMONITOREDITEMFILTERUNSUPPORTED 0x80440000 // The server does not support the requested monitored item filter.
#define UA_STATUSCODE_BADFILTERNOTALLOWED 0x80450000 // A monitoring filter cannot be used in combination with the attribute specified.
#define UA_STATUSCODE_BADSTRUCTUREMISSING 0x80460000 // A mandatory structured parameter was missing or null.
#define UA_STATUSCODE_BADEVENTFILTERINVALID 0x80470000 // The event filter is not valid.
#define UA_STATUSCODE_BADCONTENTFILTERINVALID 0x80480000 // The content filter is not valid.
#define UA_STATUSCODE_BADFILTEROPERATORINVALID 0x80c10000 // An unregognized operator was provided in a filter.
#define UA_STATUSCODE_BADFILTEROPERATORUNSUPPORTED 0x80c20000 // A valid operator was provided, but the server does not provide support for this filter operator.
#define UA_STATUSCODE_BADFILTEROPERANDCOUNTMISMATCH 0x80c30000 // The number of operands provided for the filter operator was less then expected for the operand provided.
#define UA_STATUSCODE_BADFILTEROPERANDINVALID 0x80490000 // The operand used in a content filter is not valid.
#define UA_STATUSCODE_BADFILTERELEMENTINVALID 0x80c40000 // The referenced element is not a valid element in the content filter.
#define UA_STATUSCODE_BADFILTERLITERALINVALID 0x80c50000 // The referenced literal is not a valid value.
#define UA_STATUSCODE_BADCONTINUATIONPOINTINVALID 0x804a0000 // The continuation point provide is longer valid.
#define UA_STATUSCODE_BADNOCONTINUATIONPOINTS 0x804b0000 // The operation could not be processed because all continuation points have been allocated.
#define UA_STATUSCODE_BADREFERENCETYPEIDINVALID 0x804c0000 // The operation could not be processed because all continuation points have been allocated.
#define UA_STATUSCODE_BADBROWSEDIRECTIONINVALID 0x804d0000 // The browse direction is not valid.
#define UA_STATUSCODE_BADNODENOTINVIEW 0x804e0000 // The node is not part of the view.
#define UA_STATUSCODE_BADSERVERURIINVALID 0x804f0000 // The ServerUri is not a valid URI.
#define UA_STATUSCODE_BADSERVERNAMEMISSING 0x80500000 // No ServerName was specified.
#define UA_STATUSCODE_BADDISCOVERYURLMISSING 0x80510000 // No DiscoveryUrl was specified.
#define UA_STATUSCODE_BADSEMPAHOREFILEMISSING 0x80520000 // The semaphore file specified by the client is not valid.
#define UA_STATUSCODE_BADREQUESTTYPEINVALID 0x80530000 // The security token request type is not valid.
#define UA_STATUSCODE_BADSECURITYMODEREJECTED 0x80540000 // The security mode does not meet the requirements set by the Server.
#define UA_STATUSCODE_BADSECURITYPOLICYREJECTED 0x80550000 // The security policy does not meet the requirements set by the Server.
#define UA_STATUSCODE_BADTOOMANYSESSIONS 0x80560000 // The server has reached its maximum number of sessions.
#define UA_STATUSCODE_BADUSERSIGNATUREINVALID 0x80570000 // The user token signature is missing or invalid.
#define UA_STATUSCODE_BADAPPLICATIONSIGNATUREINVALID 0x80580000 // The signature generated with the client certificate is missing or invalid.
#define UA_STATUSCODE_BADNOVALIDCERTIFICATES 0x80590000 // The client did not provide at least one software certificate that is valid and meets the profile requirements for the server.
#define UA_STATUSCODE_BADIDENTITYCHANGENOTSUPPORTED 0x80c60000 // The Server does not support changing the user identity assigned to the session.
#define UA_STATUSCODE_BADREQUESTCANCELLEDBYREQUEST 0x805a0000 // The request was cancelled by the client with the Cancel service.
#define UA_STATUSCODE_BADPARENTNODEIDINVALID 0x805b0000 // The parent node id does not to refer to a valid node.
#define UA_STATUSCODE_BADREFERENCENOTALLOWED 0x805c0000 // The reference could not be created because it violates constraints imposed by the data model.
#define UA_STATUSCODE_BADNODEIDREJECTED 0x805d0000 // The requested node id was reject because it was either invalid or server does not allow node ids to be specified by the client.
#define UA_STATUSCODE_BADNODEIDEXISTS 0x805e0000 // The requested node id is already used by another node.
#define UA_STATUSCODE_BADNODECLASSINVALID 0x805f0000 // The node class is not valid.
#define UA_STATUSCODE_BADBROWSENAMEINVALID 0x80600000 // The browse name is invalid.
#define UA_STATUSCODE_BADBROWSENAMEDUPLICATED 0x80610000 // The browse name is not unique among nodes that share the same relationship with the parent.
#define UA_STATUSCODE_BADNODEATTRIBUTESINVALID 0x80620000 // The node attributes are not valid for the node class.
#define UA_STATUSCODE_BADTYPEDEFINITIONINVALID 0x80630000 // The type definition node id does not reference an appropriate type node.
#define UA_STATUSCODE_BADSOURCENODEIDINVALID 0x80640000 // The source node id does not reference a valid node.
#define UA_STATUSCODE_BADTARGETNODEIDINVALID 0x80650000 // The target node id does not reference a valid node.
#define UA_STATUSCODE_BADDUPLICATEREFERENCENOTALLOWED 0x80660000 // The reference type between the nodes is already defined.
#define UA_STATUSCODE_BADINVALIDSELFREFERENCE 0x80670000 // The server does not allow this type of self reference on this node.
#define UA_STATUSCODE_BADREFERENCELOCALONLY 0x80680000 // The reference type is not valid for a reference to a remote server.
#define UA_STATUSCODE_BADNODELETERIGHTS 0x80690000 // The server will not allow the node to be deleted.
#define UA_STATUSCODE_UNCERTAINREFERENCENOTDELETED 0x40bc0000 // The server was not able to delete all target references.
#define UA_STATUSCODE_BADSERVERINDEXINVALID 0x806a0000 // The server index is not valid.
#define UA_STATUSCODE_BADVIEWIDUNKNOWN 0x806b0000 // The view id does not refer to a valid view node.
#define UA_STATUSCODE_BADVIEWTIMESTAMPINVALID 0x80c90000 // The view timestamp is not available or not supported.
#define UA_STATUSCODE_BADVIEWPARAMETERMISMATCH 0x80ca0000 // The view parameters are not consistent with each other.
#define UA_STATUSCODE_BADVIEWVERSIONINVALID 0x80cb0000 // The view version is not available or not supported.
#define UA_STATUSCODE_UNCERTAINNOTALLNODESAVAILABLE 0x40c00000 // The list of references may not be complete because the underlying system is not available.
#define UA_STATUSCODE_GOODRESULTSMAYBEINCOMPLETE 0x00ba0000 // The server should have followed a reference to a node in a remote server but did not. The result set may be incomplete.
#define UA_STATUSCODE_BADNOTTYPEDEFINITION 0x80c80000 // The provided Nodeid was not a type definition nodeid.
#define UA_STATUSCODE_UNCERTAINREFERENCEOUTOFSERVER 0x406c0000 // One of the references to follow in the relative path references to a node in the address space in another server.
#define UA_STATUSCODE_BADTOOMANYMATCHES 0x806d0000 // The requested operation has too many matches to return.
#define UA_STATUSCODE_BADQUERYTOOCOMPLEX 0x806e0000 // The requested operation requires too many resources in the server.
#define UA_STATUSCODE_BADNOMATCH 0x806f0000 // The requested operation has no match to return.
#define UA_STATUSCODE_BADMAXAGEINVALID 0x80700000 // The max age parameter is invalid.
#define UA_STATUSCODE_BADSECURITYMODEINSUFFICIENT 0x80e60000 // The operation is not permitted over the current secure channel.
#define UA_STATUSCODE_BADHISTORYOPERATIONINVALID 0x80710000 // The history details parameter is not valid.
#define UA_STATUSCODE_BADHISTORYOPERATIONUNSUPPORTED 0x80720000 // The server does not support the requested operation.
#define UA_STATUSCODE_BADINVALIDTIMESTAMPARGUMENT 0x80bd0000 // The defined timestamp to return was invalid.
#define UA_STATUSCODE_BADWRITENOTSUPPORTED 0x80730000 // The server not does support writing the combination of value, status and timestamps provided.
#define UA_STATUSCODE_BADTYPEMISMATCH 0x80740000 // The value supplied for the attribute is not of the same type as the attribute's value.
#define UA_STATUSCODE_BADMETHODINVALID 0x80750000 // The method id does not refer to a method for the specified object.
#define UA_STATUSCODE_BADARGUMENTSMISSING 0x80760000 // The client did not specify all of the input arguments for the method.
#define UA_STATUSCODE_BADTOOMANYSUBSCRIPTIONS 0x80770000 // The server has reached its  maximum number of subscriptions.
#define UA_STATUSCODE_BADTOOMANYPUBLISHREQUESTS 0x80780000 // The server has reached the maximum number of queued publish requests.
#define UA_STATUSCODE_BADNOSUBSCRIPTION 0x80790000 // There is no subscription available for this session.
#define UA_STATUSCODE_BADSEQUENCENUMBERUNKNOWN 0x807a0000 // The sequence number is unknown to the server.
#define UA_STATUSCODE_BADMESSAGENOTAVAILABLE 0x807b0000 // The requested notification message is no longer available.
#define UA_STATUSCODE_BADINSUFFICIENTCLIENTPROFILE 0x807c0000 // The Client of the current Session does not support one or more Profiles that are necessary for the Subscription.
#define UA_STATUSCODE_BADSTATENOTACTIVE 0x80bf0000 // The sub-state machine is not currently active.
#define UA_STATUSCODE_BADTCPSERVERTOOBUSY 0x807d0000 // The server cannot process the request because it is too busy.
#define UA_STATUSCODE_BADTCPMESSAGETYPEINVALID 0x807e0000 // The type of the message specified in the header invalid.
#define UA_STATUSCODE_BADTCPSECURECHANNELUNKNOWN 0x807f0000 // The SecureChannelId and/or TokenId are not currently in use.
#define UA_STATUSCODE_BADTCPMESSAGETOOLARGE 0x80800000 // The size of the message specified in the header is too large.
#define UA_STATUSCODE_BADTCPNOTENOUGHRESOURCES 0x80810000 // There are not enough resources to process the request.
#define UA_STATUSCODE_BADTCPINTERNALERROR 0x80820000 // An internal error occurred.
#define UA_STATUSCODE_BADTCPENDPOINTURLINVALID 0x80830000 // The Server does not recognize the QueryString specified.
#define UA_STATUSCODE_BADREQUESTINTERRUPTED 0x80840000 // The request could not be sent because of a network interruption.
#define UA_STATUSCODE_BADREQUESTTIMEOUT 0x80850000 // Timeout occurred while processing the request.
#define UA_STATUSCODE_BADSECURECHANNELCLOSED 0x80860000 // The secure channel has been closed.
#define UA_STATUSCODE_BADSECURECHANNELTOKENUNKNOWN 0x80870000 // The token has expired or is not recognized.
#define UA_STATUSCODE_BADSEQUENCENUMBERINVALID 0x80880000 // The sequence number is not valid.
#define UA_STATUSCODE_BADPROTOCOLVERSIONUNSUPPORTED 0x80be0000 // The applications do not have compatible protocol versions.
#define UA_STATUSCODE_BADCONFIGURATIONERROR 0x80890000 // There is a problem with the configuration that affects the usefulness of the value.
#define UA_STATUSCODE_BADNOTCONNECTED 0x808a0000 // The variable should receive its value from another variable, but has never been configured to do so.
#define UA_STATUSCODE_BADDEVICEFAILURE 0x808b0000 // There has been a failure in the device/data source that generates the value that has affected the value.
#define UA_STATUSCODE_BADSENSORFAILURE 0x808c0000 // There has been a failure in the sensor from which the value is derived by the device/data source.
#define UA_STATUSCODE_BADOUTOFSERVICE 0x808d0000 // The source of the data is not operational.
#define UA_STATUSCODE_BADDEADBANDFILTERINVALID 0x808e0000 // The deadband filter is not valid.
#define UA_STATUSCODE_UNCERTAINNOCOMMUNICATIONLASTUSABLEVALUE 0x408f0000 // Communication to the data source has failed. The variable value is the last value that had a good quality.
#define UA_STATUSCODE_UNCERTAINLASTUSABLEVALUE 0x40900000 // Whatever was updating this value has stopped doing so.
#define UA_STATUSCODE_UNCERTAINSUBSTITUTEVALUE 0x40910000 // The value is an operational value that was manually overwritten.
#define UA_STATUSCODE_UNCERTAININITIALVALUE 0x40920000 // The value is an initial value for a variable that normally receives its value from another variable.
#define UA_STATUSCODE_UNCERTAINSENSORNOTACCURATE 0x40930000 // The value is at one of the sensor limits.
#define UA_STATUSCODE_UNCERTAINENGINEERINGUNITSEXCEEDED 0x40940000 // The value is outside of the range of values defined for this parameter.
#define UA_STATUSCODE_UNCERTAINSUBNORMAL 0x40950000 // The value is derived from multiple sources and has less than the required number of Good sources.
#define UA_STATUSCODE_GOODLOCALOVERRIDE 0x00960000 // The value has been overridden.
#define UA_STATUSCODE_BADREFRESHINPROGRESS 0x80970000 // This Condition refresh failed, a Condition refresh operation is already in progress.
#define UA_STATUSCODE_BADCONDITIONALREADYDISABLED 0x80980000 // This condition has already been disabled.
#define UA_STATUSCODE_BADCONDITIONALREADYENABLED 0x80cc0000 // This condition has already been enabled.
#define UA_STATUSCODE_BADCONDITIONDISABLED 0x80990000 // Property not available, this condition is disabled.
#define UA_STATUSCODE_BADEVENTIDUNKNOWN 0x809a0000 // The specified event id is not recognized.
#define UA_STATUSCODE_BADEVENTNOTACKNOWLEDGEABLE 0x80bb0000 // The event cannot be acknowledged.
#define UA_STATUSCODE_BADDIALOGNOTACTIVE 0x80cd0000 // The dialog condition is not active.
#define UA_STATUSCODE_BADDIALOGRESPONSEINVALID 0x80ce0000 // The response is not valid for the dialog.
#define UA_STATUSCODE_BADCONDITIONBRANCHALREADYACKED 0x80cf0000 // The condition branch has already been acknowledged.
#define UA_STATUSCODE_BADCONDITIONBRANCHALREADYCONFIRMED 0x80d00000 // The condition branch has already been confirmed.
#define UA_STATUSCODE_BADCONDITIONALREADYSHELVED 0x80d10000 // The condition has already been shelved.
#define UA_STATUSCODE_BADCONDITIONNOTSHELVED 0x80d20000 // The condition is not currently shelved.
#define UA_STATUSCODE_BADSHELVINGTIMEOUTOFRANGE 0x80d30000 // The shelving time not within an acceptable range.
#define UA_STATUSCODE_BADNODATA 0x809b0000 // No data exists for the requested time range or event filter.
#define UA_STATUSCODE_BADBOUNDNOTFOUND 0x80d70000 // No data found to provide upper or lower bound value.
#define UA_STATUSCODE_BADBOUNDNOTSUPPORTED 0x80d80000 // The server cannot retrieve a bound for the variable.
#define UA_STATUSCODE_BADDATALOST 0x809d0000 // Data is missing due to collection started/stopped/lost.
#define UA_STATUSCODE_BADDATAUNAVAILABLE 0x809e0000 // Expected data is unavailable for the requested time range due to an un-mounted volume, an off-line archive or tape, or similar reason for temporary unavailability.
#define UA_STATUSCODE_BADENTRYEXISTS 0x809f0000 // The data or event was not successfully inserted because a matching entry exists.
#define UA_STATUSCODE_BADNOENTRYEXISTS 0x80a00000 // The data or event was not successfully updated because no matching entry exists.
#define UA_STATUSCODE_BADTIMESTAMPNOTSUPPORTED 0x80a10000 // The client requested history using a timestamp format the server does not support (i.e requested ServerTimestamp when server only supports SourceTimestamp).
#define UA_STATUSCODE_GOODENTRYINSERTED 0x00a20000 // The data or event was successfully inserted into the historical database.
#define UA_STATUSCODE_GOODENTRYREPLACED 0x00a30000 // The data or event field was successfully replaced in the historical database.
#define UA_STATUSCODE_UNCERTAINDATASUBNORMAL 0x40a40000 // The value is derived from multiple values and has less than the required number of Good values.
#define UA_STATUSCODE_GOODNODATA 0x00a50000 // No data exists for the requested time range or event filter.
#define UA_STATUSCODE_GOODMOREDATA 0x00a60000 // The data or event field was successfully replaced in the historical database.
#define UA_STATUSCODE_BADAGGREGATELISTMISMATCH 0x80d40000 // The requested number of Aggregates does not match the requested number of NodeIds.
#define UA_STATUSCODE_BADAGGREGATENOTSUPPORTED 0x80d50000 // The requested Aggregate is not support by the server.
#define UA_STATUSCODE_BADAGGREGATEINVALIDINPUTS 0x80d60000 // The aggregate value could not be derived due to invalid data inputs.
#define UA_STATUSCODE_BADAGGREGATECONFIGURATIONREJECTED 0x80da0000 // The aggregate configuration is not valid for specified node.
#define UA_STATUSCODE_GOODDATAIGNORED 0x00d90000 // The request pecifies fields which are not valid for the EventType or cannot be saved by the historian.
#define UA_STATUSCODE_BADREQUESTNOTALLOWED 0x80e40000 // The request was rejected by the server because it did not meet the criteria set by the server.
#define UA_STATUSCODE_GOODEDITED 0x00dc0000 // The value does not come from the real source and has been edited by the server.
#define UA_STATUSCODE_GOODPOSTACTIONFAILED 0x00dd0000 // There was an error in execution of these post-actions.
#define UA_STATUSCODE_UNCERTAINDOMINANTVALUECHANGED 0x40de0000 // The related EngineeringUnit has been changed but the Variable Value is still provided based on the previous unit.
#define UA_STATUSCODE_GOODDEPENDENTVALUECHANGED 0x00e00000 // A dependent value has been changed but the change has not been applied to the device.
#define UA_STATUSCODE_BADDOMINANTVALUECHANGED 0x80e10000 // The related EngineeringUnit has been changed but this change has not been applied to the device. The Variable Value is still dependent on the previous unit but its status is currently Bad.
#define UA_STATUSCODE_UNCERTAINDEPENDENTVALUECHANGED 0x40e20000 // A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is uncertain.
#define UA_STATUSCODE_BADDEPENDENTVALUECHANGED 0x80e30000 // A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is Bad.
#define UA_STATUSCODE_GOODCOMMUNICATIONEVENT 0x00a70000 // The communication layer has raised an event.
#define UA_STATUSCODE_GOODSHUTDOWNEVENT 0x00a80000 // The system is shutting down.
#define UA_STATUSCODE_GOODCALLAGAIN 0x00a90000 // The operation is not finished and needs to be called again.
#define UA_STATUSCODE_GOODNONCRITICALTIMEOUT 0x00aa0000 // A non-critical timeout occurred.
#define UA_STATUSCODE_BADINVALIDARGUMENT 0x80ab0000 // One or more arguments are invalid.
#define UA_STATUSCODE_BADCONNECTIONREJECTED 0x80ac0000 // Could not establish a network connection to remote server.
#define UA_STATUSCODE_BADDISCONNECT 0x80ad0000 // The server has disconnected from the client.
#define UA_STATUSCODE_BADCONNECTIONCLOSED 0x80ae0000 // The network connection has been closed.
#define UA_STATUSCODE_BADINVALIDSTATE 0x80af0000 // The operation cannot be completed because the object is closed, uninitialized or in some other invalid state.
#define UA_STATUSCODE_BADENDOFSTREAM 0x80b00000 // Cannot move beyond end of the stream.
#define UA_STATUSCODE_BADNODATAAVAILABLE 0x80b10000 // No data is currently available for reading from a non-blocking stream.
#define UA_STATUSCODE_BADWAITINGFORRESPONSE 0x80b20000 // The asynchronous operation is waiting for a response.
#define UA_STATUSCODE_BADOPERATIONABANDONED 0x80b30000 // The asynchronous operation was abandoned by the caller.
#define UA_STATUSCODE_BADEXPECTEDSTREAMTOBLOCK 0x80b40000 // The stream did not return all data requested (possibly because it is a non-blocking stream).
#define UA_STATUSCODE_BADWOULDBLOCK 0x80b50000 // Non blocking behaviour is required and the operation would block.
#define UA_STATUSCODE_BADSYNTAXERROR 0x80b60000 // A value had an invalid syntax.
#define UA_STATUSCODE_BADMAXCONNECTIONSREACHED 0x80b70000 // The operation could not be finished because all available connections are in use.

/* These StatusCodes are manually generated. */
#define UA_STATUSCODE_INFOTYPE_DATAVALUE 0x00000400
#define UA_STATUSCODE_INFOBITS_OVERFLOW 0x00000080

/**
 * Namespace Zero NodeIds
 * ----------------------
 * Numeric identifiers of standard-defined nodes in namespace zero. The
 * following definitions are autogenerated from the ``NodeIds.csv`` file
 * provided with the OPC UA standard. */

#define UA_NS0ID_BOOLEAN 1 // DataType
#define UA_NS0ID_SBYTE 2 // DataType
#define UA_NS0ID_BYTE 3 // DataType
#define UA_NS0ID_INT16 4 // DataType
#define UA_NS0ID_UINT16 5 // DataType
#define UA_NS0ID_INT32 6 // DataType
#define UA_NS0ID_UINT32 7 // DataType
#define UA_NS0ID_INT64 8 // DataType
#define UA_NS0ID_UINT64 9 // DataType
#define UA_NS0ID_FLOAT 10 // DataType
#define UA_NS0ID_DOUBLE 11 // DataType
#define UA_NS0ID_STRING 12 // DataType
#define UA_NS0ID_DATETIME 13 // DataType
#define UA_NS0ID_GUID 14 // DataType
#define UA_NS0ID_BYTESTRING 15 // DataType
#define UA_NS0ID_XMLELEMENT 16 // DataType
#define UA_NS0ID_NODEID 17 // DataType
#define UA_NS0ID_EXPANDEDNODEID 18 // DataType
#define UA_NS0ID_STATUSCODE 19 // DataType
#define UA_NS0ID_QUALIFIEDNAME 20 // DataType
#define UA_NS0ID_LOCALIZEDTEXT 21 // DataType
#define UA_NS0ID_STRUCTURE 22 // DataType
#define UA_NS0ID_DATAVALUE 23 // DataType
#define UA_NS0ID_BASEDATATYPE 24 // DataType
#define UA_NS0ID_DIAGNOSTICINFO 25 // DataType
#define UA_NS0ID_NUMBER 26 // DataType
#define UA_NS0ID_INTEGER 27 // DataType
#define UA_NS0ID_UINTEGER 28 // DataType
#define UA_NS0ID_ENUMERATION 29 // DataType
#define UA_NS0ID_IMAGE 30 // DataType
#define UA_NS0ID_REFERENCES 31 // ReferenceType
#define UA_NS0ID_NONHIERARCHICALREFERENCES 32 // ReferenceType
#define UA_NS0ID_HIERARCHICALREFERENCES 33 // ReferenceType
#define UA_NS0ID_HASCHILD 34 // ReferenceType
#define UA_NS0ID_ORGANIZES 35 // ReferenceType
#define UA_NS0ID_HASEVENTSOURCE 36 // ReferenceType
#define UA_NS0ID_HASMODELLINGRULE 37 // ReferenceType
#define UA_NS0ID_HASENCODING 38 // ReferenceType
#define UA_NS0ID_HASDESCRIPTION 39 // ReferenceType
#define UA_NS0ID_HASTYPEDEFINITION 40 // ReferenceType
#define UA_NS0ID_GENERATESEVENT 41 // ReferenceType
#define UA_NS0ID_AGGREGATES 44 // ReferenceType
#define UA_NS0ID_HASSUBTYPE 45 // ReferenceType
#define UA_NS0ID_HASPROPERTY 46 // ReferenceType
#define UA_NS0ID_HASCOMPONENT 47 // ReferenceType
#define UA_NS0ID_HASNOTIFIER 48 // ReferenceType
#define UA_NS0ID_HASORDEREDCOMPONENT 49 // ReferenceType
#define UA_NS0ID_FROMSTATE 51 // ReferenceType
#define UA_NS0ID_TOSTATE 52 // ReferenceType
#define UA_NS0ID_HASCAUSE 53 // ReferenceType
#define UA_NS0ID_HASEFFECT 54 // ReferenceType
#define UA_NS0ID_HASHISTORICALCONFIGURATION 56 // ReferenceType
#define UA_NS0ID_BASEOBJECTTYPE 58 // ObjectType
#define UA_NS0ID_FOLDERTYPE 61 // ObjectType
#define UA_NS0ID_BASEVARIABLETYPE 62 // VariableType
#define UA_NS0ID_BASEDATAVARIABLETYPE 63 // VariableType
#define UA_NS0ID_PROPERTYTYPE 68 // VariableType
#define UA_NS0ID_DATATYPEDESCRIPTIONTYPE 69 // VariableType
#define UA_NS0ID_DATATYPEDICTIONARYTYPE 72 // VariableType
#define UA_NS0ID_DATATYPESYSTEMTYPE 75 // ObjectType
#define UA_NS0ID_DATATYPEENCODINGTYPE 76 // ObjectType
#define UA_NS0ID_MODELLINGRULETYPE 77 // ObjectType
#define UA_NS0ID_MODELLINGRULE_MANDATORY 78 // Object
#define UA_NS0ID_MODELLINGRULE_MANDATORYSHARED 79 // Object
#define UA_NS0ID_MODELLINGRULE_OPTIONAL 80 // Object
#define UA_NS0ID_MODELLINGRULE_EXPOSESITSARRAY 83 // Object
#define UA_NS0ID_ROOTFOLDER 84 // Object
#define UA_NS0ID_OBJECTSFOLDER 85 // Object
#define UA_NS0ID_TYPESFOLDER 86 // Object
#define UA_NS0ID_VIEWSFOLDER 87 // Object
#define UA_NS0ID_OBJECTTYPESFOLDER 88 // Object
#define UA_NS0ID_VARIABLETYPESFOLDER 89 // Object
#define UA_NS0ID_DATATYPESFOLDER 90 // Object
#define UA_NS0ID_REFERENCETYPESFOLDER 91 // Object
#define UA_NS0ID_XMLSCHEMA_TYPESYSTEM 92 // Object
#define UA_NS0ID_OPCBINARYSCHEMA_TYPESYSTEM 93 // Object
#define UA_NS0ID_MODELLINGRULE_MANDATORY_NAMINGRULE 112 // Variable
#define UA_NS0ID_MODELLINGRULE_OPTIONAL_NAMINGRULE 113 // Variable
#define UA_NS0ID_MODELLINGRULE_EXPOSESITSARRAY_NAMINGRULE 114 // Variable
#define UA_NS0ID_MODELLINGRULE_MANDATORYSHARED_NAMINGRULE 116 // Variable
#define UA_NS0ID_HASSUBSTATEMACHINE 117 // ReferenceType
#define UA_NS0ID_NAMINGRULETYPE 120 // DataType
#define UA_NS0ID_DECIMAL128 121 // DataType
#define UA_NS0ID_IDTYPE 256 // DataType
#define UA_NS0ID_NODECLASS 257 // DataType
#define UA_NS0ID_NODE 258 // DataType
#define UA_NS0ID_NODE_ENCODING_DEFAULTXML 259 // Object
#define UA_NS0ID_NODE_ENCODING_DEFAULTBINARY 260 // Object
#define UA_NS0ID_OBJECTNODE 261 // DataType
#define UA_NS0ID_OBJECTNODE_ENCODING_DEFAULTXML 262 // Object
#define UA_NS0ID_OBJECTNODE_ENCODING_DEFAULTBINARY 263 // Object
#define UA_NS0ID_OBJECTTYPENODE 264 // DataType
#define UA_NS0ID_OBJECTTYPENODE_ENCODING_DEFAULTXML 265 // Object
#define UA_NS0ID_OBJECTTYPENODE_ENCODING_DEFAULTBINARY 266 // Object
#define UA_NS0ID_VARIABLENODE 267 // DataType
#define UA_NS0ID_VARIABLENODE_ENCODING_DEFAULTXML 268 // Object
#define UA_NS0ID_VARIABLENODE_ENCODING_DEFAULTBINARY 269 // Object
#define UA_NS0ID_VARIABLETYPENODE 270 // DataType
#define UA_NS0ID_VARIABLETYPENODE_ENCODING_DEFAULTXML 271 // Object
#define UA_NS0ID_VARIABLETYPENODE_ENCODING_DEFAULTBINARY 272 // Object
#define UA_NS0ID_REFERENCETYPENODE 273 // DataType
#define UA_NS0ID_REFERENCETYPENODE_ENCODING_DEFAULTXML 274 // Object
#define UA_NS0ID_REFERENCETYPENODE_ENCODING_DEFAULTBINARY 275 // Object
#define UA_NS0ID_METHODNODE 276 // DataType
#define UA_NS0ID_METHODNODE_ENCODING_DEFAULTXML 277 // Object
#define UA_NS0ID_METHODNODE_ENCODING_DEFAULTBINARY 278 // Object
#define UA_NS0ID_VIEWNODE 279 // DataType
#define UA_NS0ID_VIEWNODE_ENCODING_DEFAULTXML 280 // Object
#define UA_NS0ID_VIEWNODE_ENCODING_DEFAULTBINARY 281 // Object
#define UA_NS0ID_DATATYPENODE 282 // DataType
#define UA_NS0ID_DATATYPENODE_ENCODING_DEFAULTXML 283 // Object
#define UA_NS0ID_DATATYPENODE_ENCODING_DEFAULTBINARY 284 // Object
#define UA_NS0ID_REFERENCENODE 285 // DataType
#define UA_NS0ID_REFERENCENODE_ENCODING_DEFAULTXML 286 // Object
#define UA_NS0ID_REFERENCENODE_ENCODING_DEFAULTBINARY 287 // Object
#define UA_NS0ID_INTEGERID 288 // DataType
#define UA_NS0ID_COUNTER 289 // DataType
#define UA_NS0ID_DURATION 290 // DataType
#define UA_NS0ID_NUMERICRANGE 291 // DataType
#define UA_NS0ID_TIME 292 // DataType
#define UA_NS0ID_DATE 293 // DataType
#define UA_NS0ID_UTCTIME 294 // DataType
#define UA_NS0ID_LOCALEID 295 // DataType
#define UA_NS0ID_ARGUMENT 296 // DataType
#define UA_NS0ID_ARGUMENT_ENCODING_DEFAULTXML 297 // Object
#define UA_NS0ID_ARGUMENT_ENCODING_DEFAULTBINARY 298 // Object
#define UA_NS0ID_STATUSRESULT 299 // DataType
#define UA_NS0ID_STATUSRESULT_ENCODING_DEFAULTXML 300 // Object
#define UA_NS0ID_STATUSRESULT_ENCODING_DEFAULTBINARY 301 // Object
#define UA_NS0ID_MESSAGESECURITYMODE 302 // DataType
#define UA_NS0ID_USERTOKENTYPE 303 // DataType
#define UA_NS0ID_USERTOKENPOLICY 304 // DataType
#define UA_NS0ID_USERTOKENPOLICY_ENCODING_DEFAULTXML 305 // Object
#define UA_NS0ID_USERTOKENPOLICY_ENCODING_DEFAULTBINARY 306 // Object
#define UA_NS0ID_APPLICATIONTYPE 307 // DataType
#define UA_NS0ID_APPLICATIONDESCRIPTION 308 // DataType
#define UA_NS0ID_APPLICATIONDESCRIPTION_ENCODING_DEFAULTXML 309 // Object
#define UA_NS0ID_APPLICATIONDESCRIPTION_ENCODING_DEFAULTBINARY 310 // Object
#define UA_NS0ID_APPLICATIONINSTANCECERTIFICATE 311 // DataType
#define UA_NS0ID_ENDPOINTDESCRIPTION 312 // DataType
#define UA_NS0ID_ENDPOINTDESCRIPTION_ENCODING_DEFAULTXML 313 // Object
#define UA_NS0ID_ENDPOINTDESCRIPTION_ENCODING_DEFAULTBINARY 314 // Object
#define UA_NS0ID_SECURITYTOKENREQUESTTYPE 315 // DataType
#define UA_NS0ID_USERIDENTITYTOKEN 316 // DataType
#define UA_NS0ID_USERIDENTITYTOKEN_ENCODING_DEFAULTXML 317 // Object
#define UA_NS0ID_USERIDENTITYTOKEN_ENCODING_DEFAULTBINARY 318 // Object
#define UA_NS0ID_ANONYMOUSIDENTITYTOKEN 319 // DataType
#define UA_NS0ID_ANONYMOUSIDENTITYTOKEN_ENCODING_DEFAULTXML 320 // Object
#define UA_NS0ID_ANONYMOUSIDENTITYTOKEN_ENCODING_DEFAULTBINARY 321 // Object
#define UA_NS0ID_USERNAMEIDENTITYTOKEN 322 // DataType
#define UA_NS0ID_USERNAMEIDENTITYTOKEN_ENCODING_DEFAULTXML 323 // Object
#define UA_NS0ID_USERNAMEIDENTITYTOKEN_ENCODING_DEFAULTBINARY 324 // Object
#define UA_NS0ID_X509IDENTITYTOKEN 325 // DataType
#define UA_NS0ID_X509IDENTITYTOKEN_ENCODING_DEFAULTXML 326 // Object
#define UA_NS0ID_X509IDENTITYTOKEN_ENCODING_DEFAULTBINARY 327 // Object
#define UA_NS0ID_ENDPOINTCONFIGURATION 331 // DataType
#define UA_NS0ID_ENDPOINTCONFIGURATION_ENCODING_DEFAULTXML 332 // Object
#define UA_NS0ID_ENDPOINTCONFIGURATION_ENCODING_DEFAULTBINARY 333 // Object
#define UA_NS0ID_BUILDINFO 338 // DataType
#define UA_NS0ID_BUILDINFO_ENCODING_DEFAULTXML 339 // Object
#define UA_NS0ID_BUILDINFO_ENCODING_DEFAULTBINARY 340 // Object
#define UA_NS0ID_SIGNEDSOFTWARECERTIFICATE 344 // DataType
#define UA_NS0ID_SIGNEDSOFTWARECERTIFICATE_ENCODING_DEFAULTXML 345 // Object
#define UA_NS0ID_SIGNEDSOFTWARECERTIFICATE_ENCODING_DEFAULTBINARY 346 // Object
#define UA_NS0ID_ATTRIBUTEWRITEMASK 347 // DataType
#define UA_NS0ID_NODEATTRIBUTESMASK 348 // DataType
#define UA_NS0ID_NODEATTRIBUTES 349 // DataType
#define UA_NS0ID_NODEATTRIBUTES_ENCODING_DEFAULTXML 350 // Object
#define UA_NS0ID_NODEATTRIBUTES_ENCODING_DEFAULTBINARY 351 // Object
#define UA_NS0ID_OBJECTATTRIBUTES 352 // DataType
#define UA_NS0ID_OBJECTATTRIBUTES_ENCODING_DEFAULTXML 353 // Object
#define UA_NS0ID_OBJECTATTRIBUTES_ENCODING_DEFAULTBINARY 354 // Object
#define UA_NS0ID_VARIABLEATTRIBUTES 355 // DataType
#define UA_NS0ID_VARIABLEATTRIBUTES_ENCODING_DEFAULTXML 356 // Object
#define UA_NS0ID_VARIABLEATTRIBUTES_ENCODING_DEFAULTBINARY 357 // Object
#define UA_NS0ID_METHODATTRIBUTES 358 // DataType
#define UA_NS0ID_METHODATTRIBUTES_ENCODING_DEFAULTXML 359 // Object
#define UA_NS0ID_METHODATTRIBUTES_ENCODING_DEFAULTBINARY 360 // Object
#define UA_NS0ID_OBJECTTYPEATTRIBUTES 361 // DataType
#define UA_NS0ID_OBJECTTYPEATTRIBUTES_ENCODING_DEFAULTXML 362 // Object
#define UA_NS0ID_OBJECTTYPEATTRIBUTES_ENCODING_DEFAULTBINARY 363 // Object
#define UA_NS0ID_VARIABLETYPEATTRIBUTES 364 // DataType
#define UA_NS0ID_VARIABLETYPEATTRIBUTES_ENCODING_DEFAULTXML 365 // Object
#define UA_NS0ID_VARIABLETYPEATTRIBUTES_ENCODING_DEFAULTBINARY 366 // Object
#define UA_NS0ID_REFERENCETYPEATTRIBUTES 367 // DataType
#define UA_NS0ID_REFERENCETYPEATTRIBUTES_ENCODING_DEFAULTXML 368 // Object
#define UA_NS0ID_REFERENCETYPEATTRIBUTES_ENCODING_DEFAULTBINARY 369 // Object
#define UA_NS0ID_DATATYPEATTRIBUTES 370 // DataType
#define UA_NS0ID_DATATYPEATTRIBUTES_ENCODING_DEFAULTXML 371 // Object
#define UA_NS0ID_DATATYPEATTRIBUTES_ENCODING_DEFAULTBINARY 372 // Object
#define UA_NS0ID_VIEWATTRIBUTES 373 // DataType
#define UA_NS0ID_VIEWATTRIBUTES_ENCODING_DEFAULTXML 374 // Object
#define UA_NS0ID_VIEWATTRIBUTES_ENCODING_DEFAULTBINARY 375 // Object
#define UA_NS0ID_ADDNODESITEM 376 // DataType
#define UA_NS0ID_ADDNODESITEM_ENCODING_DEFAULTXML 377 // Object
#define UA_NS0ID_ADDNODESITEM_ENCODING_DEFAULTBINARY 378 // Object
#define UA_NS0ID_ADDREFERENCESITEM 379 // DataType
#define UA_NS0ID_ADDREFERENCESITEM_ENCODING_DEFAULTXML 380 // Object
#define UA_NS0ID_ADDREFERENCESITEM_ENCODING_DEFAULTBINARY 381 // Object
#define UA_NS0ID_DELETENODESITEM 382 // DataType
#define UA_NS0ID_DELETENODESITEM_ENCODING_DEFAULTXML 383 // Object
#define UA_NS0ID_DELETENODESITEM_ENCODING_DEFAULTBINARY 384 // Object
#define UA_NS0ID_DELETEREFERENCESITEM 385 // DataType
#define UA_NS0ID_DELETEREFERENCESITEM_ENCODING_DEFAULTXML 386 // Object
#define UA_NS0ID_DELETEREFERENCESITEM_ENCODING_DEFAULTBINARY 387 // Object
#define UA_NS0ID_SESSIONAUTHENTICATIONTOKEN 388 // DataType
#define UA_NS0ID_REQUESTHEADER 389 // DataType
#define UA_NS0ID_REQUESTHEADER_ENCODING_DEFAULTXML 390 // Object
#define UA_NS0ID_REQUESTHEADER_ENCODING_DEFAULTBINARY 391 // Object
#define UA_NS0ID_RESPONSEHEADER 392 // DataType
#define UA_NS0ID_RESPONSEHEADER_ENCODING_DEFAULTXML 393 // Object
#define UA_NS0ID_RESPONSEHEADER_ENCODING_DEFAULTBINARY 394 // Object
#define UA_NS0ID_SERVICEFAULT 395 // DataType
#define UA_NS0ID_SERVICEFAULT_ENCODING_DEFAULTXML 396 // Object
#define UA_NS0ID_SERVICEFAULT_ENCODING_DEFAULTBINARY 397 // Object
#define UA_NS0ID_FINDSERVERSREQUEST 420 // DataType
#define UA_NS0ID_FINDSERVERSREQUEST_ENCODING_DEFAULTXML 421 // Object
#define UA_NS0ID_FINDSERVERSREQUEST_ENCODING_DEFAULTBINARY 422 // Object
#define UA_NS0ID_FINDSERVERSRESPONSE 423 // DataType
#define UA_NS0ID_FINDSERVERSRESPONSE_ENCODING_DEFAULTXML 424 // Object
#define UA_NS0ID_FINDSERVERSRESPONSE_ENCODING_DEFAULTBINARY 425 // Object
#define UA_NS0ID_GETENDPOINTSREQUEST 426 // DataType
#define UA_NS0ID_GETENDPOINTSREQUEST_ENCODING_DEFAULTXML 427 // Object
#define UA_NS0ID_GETENDPOINTSREQUEST_ENCODING_DEFAULTBINARY 428 // Object
#define UA_NS0ID_GETENDPOINTSRESPONSE 429 // DataType
#define UA_NS0ID_GETENDPOINTSRESPONSE_ENCODING_DEFAULTXML 430 // Object
#define UA_NS0ID_GETENDPOINTSRESPONSE_ENCODING_DEFAULTBINARY 431 // Object
#define UA_NS0ID_REGISTEREDSERVER 432 // DataType
#define UA_NS0ID_REGISTEREDSERVER_ENCODING_DEFAULTXML 433 // Object
#define UA_NS0ID_REGISTEREDSERVER_ENCODING_DEFAULTBINARY 434 // Object
#define UA_NS0ID_REGISTERSERVERREQUEST 435 // DataType
#define UA_NS0ID_REGISTERSERVERREQUEST_ENCODING_DEFAULTXML 436 // Object
#define UA_NS0ID_REGISTERSERVERREQUEST_ENCODING_DEFAULTBINARY 437 // Object
#define UA_NS0ID_REGISTERSERVERRESPONSE 438 // DataType
#define UA_NS0ID_REGISTERSERVERRESPONSE_ENCODING_DEFAULTXML 439 // Object
#define UA_NS0ID_REGISTERSERVERRESPONSE_ENCODING_DEFAULTBINARY 440 // Object
#define UA_NS0ID_CHANNELSECURITYTOKEN 441 // DataType
#define UA_NS0ID_CHANNELSECURITYTOKEN_ENCODING_DEFAULTXML 442 // Object
#define UA_NS0ID_CHANNELSECURITYTOKEN_ENCODING_DEFAULTBINARY 443 // Object
#define UA_NS0ID_OPENSECURECHANNELREQUEST 444 // DataType
#define UA_NS0ID_OPENSECURECHANNELREQUEST_ENCODING_DEFAULTXML 445 // Object
#define UA_NS0ID_OPENSECURECHANNELREQUEST_ENCODING_DEFAULTBINARY 446 // Object
#define UA_NS0ID_OPENSECURECHANNELRESPONSE 447 // DataType
#define UA_NS0ID_OPENSECURECHANNELRESPONSE_ENCODING_DEFAULTXML 448 // Object
#define UA_NS0ID_OPENSECURECHANNELRESPONSE_ENCODING_DEFAULTBINARY 449 // Object
#define UA_NS0ID_CLOSESECURECHANNELREQUEST 450 // DataType
#define UA_NS0ID_CLOSESECURECHANNELREQUEST_ENCODING_DEFAULTXML 451 // Object
#define UA_NS0ID_CLOSESECURECHANNELREQUEST_ENCODING_DEFAULTBINARY 452 // Object
#define UA_NS0ID_CLOSESECURECHANNELRESPONSE 453 // DataType
#define UA_NS0ID_CLOSESECURECHANNELRESPONSE_ENCODING_DEFAULTXML 454 // Object
#define UA_NS0ID_CLOSESECURECHANNELRESPONSE_ENCODING_DEFAULTBINARY 455 // Object
#define UA_NS0ID_SIGNATUREDATA 456 // DataType
#define UA_NS0ID_SIGNATUREDATA_ENCODING_DEFAULTXML 457 // Object
#define UA_NS0ID_SIGNATUREDATA_ENCODING_DEFAULTBINARY 458 // Object
#define UA_NS0ID_CREATESESSIONREQUEST 459 // DataType
#define UA_NS0ID_CREATESESSIONREQUEST_ENCODING_DEFAULTXML 460 // Object
#define UA_NS0ID_CREATESESSIONREQUEST_ENCODING_DEFAULTBINARY 461 // Object
#define UA_NS0ID_CREATESESSIONRESPONSE 462 // DataType
#define UA_NS0ID_CREATESESSIONRESPONSE_ENCODING_DEFAULTXML 463 // Object
#define UA_NS0ID_CREATESESSIONRESPONSE_ENCODING_DEFAULTBINARY 464 // Object
#define UA_NS0ID_ACTIVATESESSIONREQUEST 465 // DataType
#define UA_NS0ID_ACTIVATESESSIONREQUEST_ENCODING_DEFAULTXML 466 // Object
#define UA_NS0ID_ACTIVATESESSIONREQUEST_ENCODING_DEFAULTBINARY 467 // Object
#define UA_NS0ID_ACTIVATESESSIONRESPONSE 468 // DataType
#define UA_NS0ID_ACTIVATESESSIONRESPONSE_ENCODING_DEFAULTXML 469 // Object
#define UA_NS0ID_ACTIVATESESSIONRESPONSE_ENCODING_DEFAULTBINARY 470 // Object
#define UA_NS0ID_CLOSESESSIONREQUEST 471 // DataType
#define UA_NS0ID_CLOSESESSIONREQUEST_ENCODING_DEFAULTXML 472 // Object
#define UA_NS0ID_CLOSESESSIONREQUEST_ENCODING_DEFAULTBINARY 473 // Object
#define UA_NS0ID_CLOSESESSIONRESPONSE 474 // DataType
#define UA_NS0ID_CLOSESESSIONRESPONSE_ENCODING_DEFAULTXML 475 // Object
#define UA_NS0ID_CLOSESESSIONRESPONSE_ENCODING_DEFAULTBINARY 476 // Object
#define UA_NS0ID_CANCELREQUEST 477 // DataType
#define UA_NS0ID_CANCELREQUEST_ENCODING_DEFAULTXML 478 // Object
#define UA_NS0ID_CANCELREQUEST_ENCODING_DEFAULTBINARY 479 // Object
#define UA_NS0ID_CANCELRESPONSE 480 // DataType
#define UA_NS0ID_CANCELRESPONSE_ENCODING_DEFAULTXML 481 // Object
#define UA_NS0ID_CANCELRESPONSE_ENCODING_DEFAULTBINARY 482 // Object
#define UA_NS0ID_ADDNODESRESULT 483 // DataType
#define UA_NS0ID_ADDNODESRESULT_ENCODING_DEFAULTXML 484 // Object
#define UA_NS0ID_ADDNODESRESULT_ENCODING_DEFAULTBINARY 485 // Object
#define UA_NS0ID_ADDNODESREQUEST 486 // DataType
#define UA_NS0ID_ADDNODESREQUEST_ENCODING_DEFAULTXML 487 // Object
#define UA_NS0ID_ADDNODESREQUEST_ENCODING_DEFAULTBINARY 488 // Object
#define UA_NS0ID_ADDNODESRESPONSE 489 // DataType
#define UA_NS0ID_ADDNODESRESPONSE_ENCODING_DEFAULTXML 490 // Object
#define UA_NS0ID_ADDNODESRESPONSE_ENCODING_DEFAULTBINARY 491 // Object
#define UA_NS0ID_ADDREFERENCESREQUEST 492 // DataType
#define UA_NS0ID_ADDREFERENCESREQUEST_ENCODING_DEFAULTXML 493 // Object
#define UA_NS0ID_ADDREFERENCESREQUEST_ENCODING_DEFAULTBINARY 494 // Object
#define UA_NS0ID_ADDREFERENCESRESPONSE 495 // DataType
#define UA_NS0ID_ADDREFERENCESRESPONSE_ENCODING_DEFAULTXML 496 // Object
#define UA_NS0ID_ADDREFERENCESRESPONSE_ENCODING_DEFAULTBINARY 497 // Object
#define UA_NS0ID_DELETENODESREQUEST 498 // DataType
#define UA_NS0ID_DELETENODESREQUEST_ENCODING_DEFAULTXML 499 // Object
#define UA_NS0ID_DELETENODESREQUEST_ENCODING_DEFAULTBINARY 500 // Object
#define UA_NS0ID_DELETENODESRESPONSE 501 // DataType
#define UA_NS0ID_DELETENODESRESPONSE_ENCODING_DEFAULTXML 502 // Object
#define UA_NS0ID_DELETENODESRESPONSE_ENCODING_DEFAULTBINARY 503 // Object
#define UA_NS0ID_DELETEREFERENCESREQUEST 504 // DataType
#define UA_NS0ID_DELETEREFERENCESREQUEST_ENCODING_DEFAULTXML 505 // Object
#define UA_NS0ID_DELETEREFERENCESREQUEST_ENCODING_DEFAULTBINARY 506 // Object
#define UA_NS0ID_DELETEREFERENCESRESPONSE 507 // DataType
#define UA_NS0ID_DELETEREFERENCESRESPONSE_ENCODING_DEFAULTXML 508 // Object
#define UA_NS0ID_DELETEREFERENCESRESPONSE_ENCODING_DEFAULTBINARY 509 // Object
#define UA_NS0ID_BROWSEDIRECTION 510 // DataType
#define UA_NS0ID_VIEWDESCRIPTION 511 // DataType
#define UA_NS0ID_VIEWDESCRIPTION_ENCODING_DEFAULTXML 512 // Object
#define UA_NS0ID_VIEWDESCRIPTION_ENCODING_DEFAULTBINARY 513 // Object
#define UA_NS0ID_BROWSEDESCRIPTION 514 // DataType
#define UA_NS0ID_BROWSEDESCRIPTION_ENCODING_DEFAULTXML 515 // Object
#define UA_NS0ID_BROWSEDESCRIPTION_ENCODING_DEFAULTBINARY 516 // Object
#define UA_NS0ID_BROWSERESULTMASK 517 // DataType
#define UA_NS0ID_REFERENCEDESCRIPTION 518 // DataType
#define UA_NS0ID_REFERENCEDESCRIPTION_ENCODING_DEFAULTXML 519 // Object
#define UA_NS0ID_REFERENCEDESCRIPTION_ENCODING_DEFAULTBINARY 520 // Object
#define UA_NS0ID_CONTINUATIONPOINT 521 // DataType
#define UA_NS0ID_BROWSERESULT 522 // DataType
#define UA_NS0ID_BROWSERESULT_ENCODING_DEFAULTXML 523 // Object
#define UA_NS0ID_BROWSERESULT_ENCODING_DEFAULTBINARY 524 // Object
#define UA_NS0ID_BROWSEREQUEST 525 // DataType
#define UA_NS0ID_BROWSEREQUEST_ENCODING_DEFAULTXML 526 // Object
#define UA_NS0ID_BROWSEREQUEST_ENCODING_DEFAULTBINARY 527 // Object
#define UA_NS0ID_BROWSERESPONSE 528 // DataType
#define UA_NS0ID_BROWSERESPONSE_ENCODING_DEFAULTXML 529 // Object
#define UA_NS0ID_BROWSERESPONSE_ENCODING_DEFAULTBINARY 530 // Object
#define UA_NS0ID_BROWSENEXTREQUEST 531 // DataType
#define UA_NS0ID_BROWSENEXTREQUEST_ENCODING_DEFAULTXML 532 // Object
#define UA_NS0ID_BROWSENEXTREQUEST_ENCODING_DEFAULTBINARY 533 // Object
#define UA_NS0ID_BROWSENEXTRESPONSE 534 // DataType
#define UA_NS0ID_BROWSENEXTRESPONSE_ENCODING_DEFAULTXML 535 // Object
#define UA_NS0ID_BROWSENEXTRESPONSE_ENCODING_DEFAULTBINARY 536 // Object
#define UA_NS0ID_RELATIVEPATHELEMENT 537 // DataType
#define UA_NS0ID_RELATIVEPATHELEMENT_ENCODING_DEFAULTXML 538 // Object
#define UA_NS0ID_RELATIVEPATHELEMENT_ENCODING_DEFAULTBINARY 539 // Object
#define UA_NS0ID_RELATIVEPATH 540 // DataType
#define UA_NS0ID_RELATIVEPATH_ENCODING_DEFAULTXML 541 // Object
#define UA_NS0ID_RELATIVEPATH_ENCODING_DEFAULTBINARY 542 // Object
#define UA_NS0ID_BROWSEPATH 543 // DataType
#define UA_NS0ID_BROWSEPATH_ENCODING_DEFAULTXML 544 // Object
#define UA_NS0ID_BROWSEPATH_ENCODING_DEFAULTBINARY 545 // Object
#define UA_NS0ID_BROWSEPATHTARGET 546 // DataType
#define UA_NS0ID_BROWSEPATHTARGET_ENCODING_DEFAULTXML 547 // Object
#define UA_NS0ID_BROWSEPATHTARGET_ENCODING_DEFAULTBINARY 548 // Object
#define UA_NS0ID_BROWSEPATHRESULT 549 // DataType
#define UA_NS0ID_BROWSEPATHRESULT_ENCODING_DEFAULTXML 550 // Object
#define UA_NS0ID_BROWSEPATHRESULT_ENCODING_DEFAULTBINARY 551 // Object
#define UA_NS0ID_TRANSLATEBROWSEPATHSTONODEIDSREQUEST 552 // DataType
#define UA_NS0ID_TRANSLATEBROWSEPATHSTONODEIDSREQUEST_ENCODING_DEFAULTXML 553 // Object
#define UA_NS0ID_TRANSLATEBROWSEPATHSTONODEIDSREQUEST_ENCODING_DEFAULTBINARY 554 // Object
#define UA_NS0ID_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE 555 // DataType
#define UA_NS0ID_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE_ENCODING_DEFAULTXML 556 // Object
#define UA_NS0ID_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE_ENCODING_DEFAULTBINARY 557 // Object
#define UA_NS0ID_REGISTERNODESREQUEST 558 // DataType
#define UA_NS0ID_REGISTERNODESREQUEST_ENCODING_DEFAULTXML 559 // Object
#define UA_NS0ID_REGISTERNODESREQUEST_ENCODING_DEFAULTBINARY 560 // Object
#define UA_NS0ID_REGISTERNODESRESPONSE 561 // DataType
#define UA_NS0ID_REGISTERNODESRESPONSE_ENCODING_DEFAULTXML 562 // Object
#define UA_NS0ID_REGISTERNODESRESPONSE_ENCODING_DEFAULTBINARY 563 // Object
#define UA_NS0ID_UNREGISTERNODESREQUEST 564 // DataType
#define UA_NS0ID_UNREGISTERNODESREQUEST_ENCODING_DEFAULTXML 565 // Object
#define UA_NS0ID_UNREGISTERNODESREQUEST_ENCODING_DEFAULTBINARY 566 // Object
#define UA_NS0ID_UNREGISTERNODESRESPONSE 567 // DataType
#define UA_NS0ID_UNREGISTERNODESRESPONSE_ENCODING_DEFAULTXML 568 // Object
#define UA_NS0ID_UNREGISTERNODESRESPONSE_ENCODING_DEFAULTBINARY 569 // Object
#define UA_NS0ID_QUERYDATADESCRIPTION 570 // DataType
#define UA_NS0ID_QUERYDATADESCRIPTION_ENCODING_DEFAULTXML 571 // Object
#define UA_NS0ID_QUERYDATADESCRIPTION_ENCODING_DEFAULTBINARY 572 // Object
#define UA_NS0ID_NODETYPEDESCRIPTION 573 // DataType
#define UA_NS0ID_NODETYPEDESCRIPTION_ENCODING_DEFAULTXML 574 // Object
#define UA_NS0ID_NODETYPEDESCRIPTION_ENCODING_DEFAULTBINARY 575 // Object
#define UA_NS0ID_FILTEROPERATOR 576 // DataType
#define UA_NS0ID_QUERYDATASET 577 // DataType
#define UA_NS0ID_QUERYDATASET_ENCODING_DEFAULTXML 578 // Object
#define UA_NS0ID_QUERYDATASET_ENCODING_DEFAULTBINARY 579 // Object
#define UA_NS0ID_NODEREFERENCE 580 // DataType
#define UA_NS0ID_NODEREFERENCE_ENCODING_DEFAULTXML 581 // Object
#define UA_NS0ID_NODEREFERENCE_ENCODING_DEFAULTBINARY 582 // Object
#define UA_NS0ID_CONTENTFILTERELEMENT 583 // DataType
#define UA_NS0ID_CONTENTFILTERELEMENT_ENCODING_DEFAULTXML 584 // Object
#define UA_NS0ID_CONTENTFILTERELEMENT_ENCODING_DEFAULTBINARY 585 // Object
#define UA_NS0ID_CONTENTFILTER 586 // DataType
#define UA_NS0ID_CONTENTFILTER_ENCODING_DEFAULTXML 587 // Object
#define UA_NS0ID_CONTENTFILTER_ENCODING_DEFAULTBINARY 588 // Object
#define UA_NS0ID_FILTEROPERAND 589 // DataType
#define UA_NS0ID_FILTEROPERAND_ENCODING_DEFAULTXML 590 // Object
#define UA_NS0ID_FILTEROPERAND_ENCODING_DEFAULTBINARY 591 // Object
#define UA_NS0ID_ELEMENTOPERAND 592 // DataType
#define UA_NS0ID_ELEMENTOPERAND_ENCODING_DEFAULTXML 593 // Object
#define UA_NS0ID_ELEMENTOPERAND_ENCODING_DEFAULTBINARY 594 // Object
#define UA_NS0ID_LITERALOPERAND 595 // DataType
#define UA_NS0ID_LITERALOPERAND_ENCODING_DEFAULTXML 596 // Object
#define UA_NS0ID_LITERALOPERAND_ENCODING_DEFAULTBINARY 597 // Object
#define UA_NS0ID_ATTRIBUTEOPERAND 598 // DataType
#define UA_NS0ID_ATTRIBUTEOPERAND_ENCODING_DEFAULTXML 599 // Object
#define UA_NS0ID_ATTRIBUTEOPERAND_ENCODING_DEFAULTBINARY 600 // Object
#define UA_NS0ID_SIMPLEATTRIBUTEOPERAND 601 // DataType
#define UA_NS0ID_SIMPLEATTRIBUTEOPERAND_ENCODING_DEFAULTXML 602 // Object
#define UA_NS0ID_SIMPLEATTRIBUTEOPERAND_ENCODING_DEFAULTBINARY 603 // Object
#define UA_NS0ID_CONTENTFILTERELEMENTRESULT 604 // DataType
#define UA_NS0ID_CONTENTFILTERELEMENTRESULT_ENCODING_DEFAULTXML 605 // Object
#define UA_NS0ID_CONTENTFILTERELEMENTRESULT_ENCODING_DEFAULTBINARY 606 // Object
#define UA_NS0ID_CONTENTFILTERRESULT 607 // DataType
#define UA_NS0ID_CONTENTFILTERRESULT_ENCODING_DEFAULTXML 608 // Object
#define UA_NS0ID_CONTENTFILTERRESULT_ENCODING_DEFAULTBINARY 609 // Object
#define UA_NS0ID_PARSINGRESULT 610 // DataType
#define UA_NS0ID_PARSINGRESULT_ENCODING_DEFAULTXML 611 // Object
#define UA_NS0ID_PARSINGRESULT_ENCODING_DEFAULTBINARY 612 // Object
#define UA_NS0ID_QUERYFIRSTREQUEST 613 // DataType
#define UA_NS0ID_QUERYFIRSTREQUEST_ENCODING_DEFAULTXML 614 // Object
#define UA_NS0ID_QUERYFIRSTREQUEST_ENCODING_DEFAULTBINARY 615 // Object
#define UA_NS0ID_QUERYFIRSTRESPONSE 616 // DataType
#define UA_NS0ID_QUERYFIRSTRESPONSE_ENCODING_DEFAULTXML 617 // Object
#define UA_NS0ID_QUERYFIRSTRESPONSE_ENCODING_DEFAULTBINARY 618 // Object
#define UA_NS0ID_QUERYNEXTREQUEST 619 // DataType
#define UA_NS0ID_QUERYNEXTREQUEST_ENCODING_DEFAULTXML 620 // Object
#define UA_NS0ID_QUERYNEXTREQUEST_ENCODING_DEFAULTBINARY 621 // Object
#define UA_NS0ID_QUERYNEXTRESPONSE 622 // DataType
#define UA_NS0ID_QUERYNEXTRESPONSE_ENCODING_DEFAULTXML 623 // Object
#define UA_NS0ID_QUERYNEXTRESPONSE_ENCODING_DEFAULTBINARY 624 // Object
#define UA_NS0ID_TIMESTAMPSTORETURN 625 // DataType
#define UA_NS0ID_READVALUEID 626 // DataType
#define UA_NS0ID_READVALUEID_ENCODING_DEFAULTXML 627 // Object
#define UA_NS0ID_READVALUEID_ENCODING_DEFAULTBINARY 628 // Object
#define UA_NS0ID_READREQUEST 629 // DataType
#define UA_NS0ID_READREQUEST_ENCODING_DEFAULTXML 630 // Object
#define UA_NS0ID_READREQUEST_ENCODING_DEFAULTBINARY 631 // Object
#define UA_NS0ID_READRESPONSE 632 // DataType
#define UA_NS0ID_READRESPONSE_ENCODING_DEFAULTXML 633 // Object
#define UA_NS0ID_READRESPONSE_ENCODING_DEFAULTBINARY 634 // Object
#define UA_NS0ID_HISTORYREADVALUEID 635 // DataType
#define UA_NS0ID_HISTORYREADVALUEID_ENCODING_DEFAULTXML 636 // Object
#define UA_NS0ID_HISTORYREADVALUEID_ENCODING_DEFAULTBINARY 637 // Object
#define UA_NS0ID_HISTORYREADRESULT 638 // DataType
#define UA_NS0ID_HISTORYREADRESULT_ENCODING_DEFAULTXML 639 // Object
#define UA_NS0ID_HISTORYREADRESULT_ENCODING_DEFAULTBINARY 640 // Object
#define UA_NS0ID_HISTORYREADDETAILS 641 // DataType
#define UA_NS0ID_HISTORYREADDETAILS_ENCODING_DEFAULTXML 642 // Object
#define UA_NS0ID_HISTORYREADDETAILS_ENCODING_DEFAULTBINARY 643 // Object
#define UA_NS0ID_READEVENTDETAILS 644 // DataType
#define UA_NS0ID_READEVENTDETAILS_ENCODING_DEFAULTXML 645 // Object
#define UA_NS0ID_READEVENTDETAILS_ENCODING_DEFAULTBINARY 646 // Object
#define UA_NS0ID_READRAWMODIFIEDDETAILS 647 // DataType
#define UA_NS0ID_READRAWMODIFIEDDETAILS_ENCODING_DEFAULTXML 648 // Object
#define UA_NS0ID_READRAWMODIFIEDDETAILS_ENCODING_DEFAULTBINARY 649 // Object
#define UA_NS0ID_READPROCESSEDDETAILS 650 // DataType
#define UA_NS0ID_READPROCESSEDDETAILS_ENCODING_DEFAULTXML 651 // Object
#define UA_NS0ID_READPROCESSEDDETAILS_ENCODING_DEFAULTBINARY 652 // Object
#define UA_NS0ID_READATTIMEDETAILS 653 // DataType
#define UA_NS0ID_READATTIMEDETAILS_ENCODING_DEFAULTXML 654 // Object
#define UA_NS0ID_READATTIMEDETAILS_ENCODING_DEFAULTBINARY 655 // Object
#define UA_NS0ID_HISTORYDATA 656 // DataType
#define UA_NS0ID_HISTORYDATA_ENCODING_DEFAULTXML 657 // Object
#define UA_NS0ID_HISTORYDATA_ENCODING_DEFAULTBINARY 658 // Object
#define UA_NS0ID_HISTORYEVENT 659 // DataType
#define UA_NS0ID_HISTORYEVENT_ENCODING_DEFAULTXML 660 // Object
#define UA_NS0ID_HISTORYEVENT_ENCODING_DEFAULTBINARY 661 // Object
#define UA_NS0ID_HISTORYREADREQUEST 662 // DataType
#define UA_NS0ID_HISTORYREADREQUEST_ENCODING_DEFAULTXML 663 // Object
#define UA_NS0ID_HISTORYREADREQUEST_ENCODING_DEFAULTBINARY 664 // Object
#define UA_NS0ID_HISTORYREADRESPONSE 665 // DataType
#define UA_NS0ID_HISTORYREADRESPONSE_ENCODING_DEFAULTXML 666 // Object
#define UA_NS0ID_HISTORYREADRESPONSE_ENCODING_DEFAULTBINARY 667 // Object
#define UA_NS0ID_WRITEVALUE 668 // DataType
#define UA_NS0ID_WRITEVALUE_ENCODING_DEFAULTXML 669 // Object
#define UA_NS0ID_WRITEVALUE_ENCODING_DEFAULTBINARY 670 // Object
#define UA_NS0ID_WRITEREQUEST 671 // DataType
#define UA_NS0ID_WRITEREQUEST_ENCODING_DEFAULTXML 672 // Object
#define UA_NS0ID_WRITEREQUEST_ENCODING_DEFAULTBINARY 673 // Object
#define UA_NS0ID_WRITERESPONSE 674 // DataType
#define UA_NS0ID_WRITERESPONSE_ENCODING_DEFAULTXML 675 // Object
#define UA_NS0ID_WRITERESPONSE_ENCODING_DEFAULTBINARY 676 // Object
#define UA_NS0ID_HISTORYUPDATEDETAILS 677 // DataType
#define UA_NS0ID_HISTORYUPDATEDETAILS_ENCODING_DEFAULTXML 678 // Object
#define UA_NS0ID_HISTORYUPDATEDETAILS_ENCODING_DEFAULTBINARY 679 // Object
#define UA_NS0ID_UPDATEDATADETAILS 680 // DataType
#define UA_NS0ID_UPDATEDATADETAILS_ENCODING_DEFAULTXML 681 // Object
#define UA_NS0ID_UPDATEDATADETAILS_ENCODING_DEFAULTBINARY 682 // Object
#define UA_NS0ID_UPDATEEVENTDETAILS 683 // DataType
#define UA_NS0ID_UPDATEEVENTDETAILS_ENCODING_DEFAULTXML 684 // Object
#define UA_NS0ID_UPDATEEVENTDETAILS_ENCODING_DEFAULTBINARY 685 // Object
#define UA_NS0ID_DELETERAWMODIFIEDDETAILS 686 // DataType
#define UA_NS0ID_DELETERAWMODIFIEDDETAILS_ENCODING_DEFAULTXML 687 // Object
#define UA_NS0ID_DELETERAWMODIFIEDDETAILS_ENCODING_DEFAULTBINARY 688 // Object
#define UA_NS0ID_DELETEATTIMEDETAILS 689 // DataType
#define UA_NS0ID_DELETEATTIMEDETAILS_ENCODING_DEFAULTXML 690 // Object
#define UA_NS0ID_DELETEATTIMEDETAILS_ENCODING_DEFAULTBINARY 691 // Object
#define UA_NS0ID_DELETEEVENTDETAILS 692 // DataType
#define UA_NS0ID_DELETEEVENTDETAILS_ENCODING_DEFAULTXML 693 // Object
#define UA_NS0ID_DELETEEVENTDETAILS_ENCODING_DEFAULTBINARY 694 // Object
#define UA_NS0ID_HISTORYUPDATERESULT 695 // DataType
#define UA_NS0ID_HISTORYUPDATERESULT_ENCODING_DEFAULTXML 696 // Object
#define UA_NS0ID_HISTORYUPDATERESULT_ENCODING_DEFAULTBINARY 697 // Object
#define UA_NS0ID_HISTORYUPDATEREQUEST 698 // DataType
#define UA_NS0ID_HISTORYUPDATEREQUEST_ENCODING_DEFAULTXML 699 // Object
#define UA_NS0ID_HISTORYUPDATEREQUEST_ENCODING_DEFAULTBINARY 700 // Object
#define UA_NS0ID_HISTORYUPDATERESPONSE 701 // DataType
#define UA_NS0ID_HISTORYUPDATERESPONSE_ENCODING_DEFAULTXML 702 // Object
#define UA_NS0ID_HISTORYUPDATERESPONSE_ENCODING_DEFAULTBINARY 703 // Object
#define UA_NS0ID_CALLMETHODREQUEST 704 // DataType
#define UA_NS0ID_CALLMETHODREQUEST_ENCODING_DEFAULTXML 705 // Object
#define UA_NS0ID_CALLMETHODREQUEST_ENCODING_DEFAULTBINARY 706 // Object
#define UA_NS0ID_CALLMETHODRESULT 707 // DataType
#define UA_NS0ID_CALLMETHODRESULT_ENCODING_DEFAULTXML 708 // Object
#define UA_NS0ID_CALLMETHODRESULT_ENCODING_DEFAULTBINARY 709 // Object
#define UA_NS0ID_CALLREQUEST 710 // DataType
#define UA_NS0ID_CALLREQUEST_ENCODING_DEFAULTXML 711 // Object
#define UA_NS0ID_CALLREQUEST_ENCODING_DEFAULTBINARY 712 // Object
#define UA_NS0ID_CALLRESPONSE 713 // DataType
#define UA_NS0ID_CALLRESPONSE_ENCODING_DEFAULTXML 714 // Object
#define UA_NS0ID_CALLRESPONSE_ENCODING_DEFAULTBINARY 715 // Object
#define UA_NS0ID_MONITORINGMODE 716 // DataType
#define UA_NS0ID_DATACHANGETRIGGER 717 // DataType
#define UA_NS0ID_DEADBANDTYPE 718 // DataType
#define UA_NS0ID_MONITORINGFILTER 719 // DataType
#define UA_NS0ID_MONITORINGFILTER_ENCODING_DEFAULTXML 720 // Object
#define UA_NS0ID_MONITORINGFILTER_ENCODING_DEFAULTBINARY 721 // Object
#define UA_NS0ID_DATACHANGEFILTER 722 // DataType
#define UA_NS0ID_DATACHANGEFILTER_ENCODING_DEFAULTXML 723 // Object
#define UA_NS0ID_DATACHANGEFILTER_ENCODING_DEFAULTBINARY 724 // Object
#define UA_NS0ID_EVENTFILTER 725 // DataType
#define UA_NS0ID_EVENTFILTER_ENCODING_DEFAULTXML 726 // Object
#define UA_NS0ID_EVENTFILTER_ENCODING_DEFAULTBINARY 727 // Object
#define UA_NS0ID_AGGREGATEFILTER 728 // DataType
#define UA_NS0ID_AGGREGATEFILTER_ENCODING_DEFAULTXML 729 // Object
#define UA_NS0ID_AGGREGATEFILTER_ENCODING_DEFAULTBINARY 730 // Object
#define UA_NS0ID_MONITORINGFILTERRESULT 731 // DataType
#define UA_NS0ID_MONITORINGFILTERRESULT_ENCODING_DEFAULTXML 732 // Object
#define UA_NS0ID_MONITORINGFILTERRESULT_ENCODING_DEFAULTBINARY 733 // Object
#define UA_NS0ID_EVENTFILTERRESULT 734 // DataType
#define UA_NS0ID_EVENTFILTERRESULT_ENCODING_DEFAULTXML 735 // Object
#define UA_NS0ID_EVENTFILTERRESULT_ENCODING_DEFAULTBINARY 736 // Object
#define UA_NS0ID_AGGREGATEFILTERRESULT 737 // DataType
#define UA_NS0ID_AGGREGATEFILTERRESULT_ENCODING_DEFAULTXML 738 // Object
#define UA_NS0ID_AGGREGATEFILTERRESULT_ENCODING_DEFAULTBINARY 739 // Object
#define UA_NS0ID_MONITORINGPARAMETERS 740 // DataType
#define UA_NS0ID_MONITORINGPARAMETERS_ENCODING_DEFAULTXML 741 // Object
#define UA_NS0ID_MONITORINGPARAMETERS_ENCODING_DEFAULTBINARY 742 // Object
#define UA_NS0ID_MONITOREDITEMCREATEREQUEST 743 // DataType
#define UA_NS0ID_MONITOREDITEMCREATEREQUEST_ENCODING_DEFAULTXML 744 // Object
#define UA_NS0ID_MONITOREDITEMCREATEREQUEST_ENCODING_DEFAULTBINARY 745 // Object
#define UA_NS0ID_MONITOREDITEMCREATERESULT 746 // DataType
#define UA_NS0ID_MONITOREDITEMCREATERESULT_ENCODING_DEFAULTXML 747 // Object
#define UA_NS0ID_MONITOREDITEMCREATERESULT_ENCODING_DEFAULTBINARY 748 // Object
#define UA_NS0ID_CREATEMONITOREDITEMSREQUEST 749 // DataType
#define UA_NS0ID_CREATEMONITOREDITEMSREQUEST_ENCODING_DEFAULTXML 750 // Object
#define UA_NS0ID_CREATEMONITOREDITEMSREQUEST_ENCODING_DEFAULTBINARY 751 // Object
#define UA_NS0ID_CREATEMONITOREDITEMSRESPONSE 752 // DataType
#define UA_NS0ID_CREATEMONITOREDITEMSRESPONSE_ENCODING_DEFAULTXML 753 // Object
#define UA_NS0ID_CREATEMONITOREDITEMSRESPONSE_ENCODING_DEFAULTBINARY 754 // Object
#define UA_NS0ID_MONITOREDITEMMODIFYREQUEST 755 // DataType
#define UA_NS0ID_MONITOREDITEMMODIFYREQUEST_ENCODING_DEFAULTXML 756 // Object
#define UA_NS0ID_MONITOREDITEMMODIFYREQUEST_ENCODING_DEFAULTBINARY 757 // Object
#define UA_NS0ID_MONITOREDITEMMODIFYRESULT 758 // DataType
#define UA_NS0ID_MONITOREDITEMMODIFYRESULT_ENCODING_DEFAULTXML 759 // Object
#define UA_NS0ID_MONITOREDITEMMODIFYRESULT_ENCODING_DEFAULTBINARY 760 // Object
#define UA_NS0ID_MODIFYMONITOREDITEMSREQUEST 761 // DataType
#define UA_NS0ID_MODIFYMONITOREDITEMSREQUEST_ENCODING_DEFAULTXML 762 // Object
#define UA_NS0ID_MODIFYMONITOREDITEMSREQUEST_ENCODING_DEFAULTBINARY 763 // Object
#define UA_NS0ID_MODIFYMONITOREDITEMSRESPONSE 764 // DataType
#define UA_NS0ID_MODIFYMONITOREDITEMSRESPONSE_ENCODING_DEFAULTXML 765 // Object
#define UA_NS0ID_MODIFYMONITOREDITEMSRESPONSE_ENCODING_DEFAULTBINARY 766 // Object
#define UA_NS0ID_SETMONITORINGMODEREQUEST 767 // DataType
#define UA_NS0ID_SETMONITORINGMODEREQUEST_ENCODING_DEFAULTXML 768 // Object
#define UA_NS0ID_SETMONITORINGMODEREQUEST_ENCODING_DEFAULTBINARY 769 // Object
#define UA_NS0ID_SETMONITORINGMODERESPONSE 770 // DataType
#define UA_NS0ID_SETMONITORINGMODERESPONSE_ENCODING_DEFAULTXML 771 // Object
#define UA_NS0ID_SETMONITORINGMODERESPONSE_ENCODING_DEFAULTBINARY 772 // Object
#define UA_NS0ID_SETTRIGGERINGREQUEST 773 // DataType
#define UA_NS0ID_SETTRIGGERINGREQUEST_ENCODING_DEFAULTXML 774 // Object
#define UA_NS0ID_SETTRIGGERINGREQUEST_ENCODING_DEFAULTBINARY 775 // Object
#define UA_NS0ID_SETTRIGGERINGRESPONSE 776 // DataType
#define UA_NS0ID_SETTRIGGERINGRESPONSE_ENCODING_DEFAULTXML 777 // Object
#define UA_NS0ID_SETTRIGGERINGRESPONSE_ENCODING_DEFAULTBINARY 778 // Object
#define UA_NS0ID_DELETEMONITOREDITEMSREQUEST 779 // DataType
#define UA_NS0ID_DELETEMONITOREDITEMSREQUEST_ENCODING_DEFAULTXML 780 // Object
#define UA_NS0ID_DELETEMONITOREDITEMSREQUEST_ENCODING_DEFAULTBINARY 781 // Object
#define UA_NS0ID_DELETEMONITOREDITEMSRESPONSE 782 // DataType
#define UA_NS0ID_DELETEMONITOREDITEMSRESPONSE_ENCODING_DEFAULTXML 783 // Object
#define UA_NS0ID_DELETEMONITOREDITEMSRESPONSE_ENCODING_DEFAULTBINARY 784 // Object
#define UA_NS0ID_CREATESUBSCRIPTIONREQUEST 785 // DataType
#define UA_NS0ID_CREATESUBSCRIPTIONREQUEST_ENCODING_DEFAULTXML 786 // Object
#define UA_NS0ID_CREATESUBSCRIPTIONREQUEST_ENCODING_DEFAULTBINARY 787 // Object
#define UA_NS0ID_CREATESUBSCRIPTIONRESPONSE 788 // DataType
#define UA_NS0ID_CREATESUBSCRIPTIONRESPONSE_ENCODING_DEFAULTXML 789 // Object
#define UA_NS0ID_CREATESUBSCRIPTIONRESPONSE_ENCODING_DEFAULTBINARY 790 // Object
#define UA_NS0ID_MODIFYSUBSCRIPTIONREQUEST 791 // DataType
#define UA_NS0ID_MODIFYSUBSCRIPTIONREQUEST_ENCODING_DEFAULTXML 792 // Object
#define UA_NS0ID_MODIFYSUBSCRIPTIONREQUEST_ENCODING_DEFAULTBINARY 793 // Object
#define UA_NS0ID_MODIFYSUBSCRIPTIONRESPONSE 794 // DataType
#define UA_NS0ID_MODIFYSUBSCRIPTIONRESPONSE_ENCODING_DEFAULTXML 795 // Object
#define UA_NS0ID_MODIFYSUBSCRIPTIONRESPONSE_ENCODING_DEFAULTBINARY 796 // Object
#define UA_NS0ID_SETPUBLISHINGMODEREQUEST 797 // DataType
#define UA_NS0ID_SETPUBLISHINGMODEREQUEST_ENCODING_DEFAULTXML 798 // Object
#define UA_NS0ID_SETPUBLISHINGMODEREQUEST_ENCODING_DEFAULTBINARY 799 // Object
#define UA_NS0ID_SETPUBLISHINGMODERESPONSE 800 // DataType
#define UA_NS0ID_SETPUBLISHINGMODERESPONSE_ENCODING_DEFAULTXML 801 // Object
#define UA_NS0ID_SETPUBLISHINGMODERESPONSE_ENCODING_DEFAULTBINARY 802 // Object
#define UA_NS0ID_NOTIFICATIONMESSAGE 803 // DataType
#define UA_NS0ID_NOTIFICATIONMESSAGE_ENCODING_DEFAULTXML 804 // Object
#define UA_NS0ID_NOTIFICATIONMESSAGE_ENCODING_DEFAULTBINARY 805 // Object
#define UA_NS0ID_MONITOREDITEMNOTIFICATION 806 // DataType
#define UA_NS0ID_MONITOREDITEMNOTIFICATION_ENCODING_DEFAULTXML 807 // Object
#define UA_NS0ID_MONITOREDITEMNOTIFICATION_ENCODING_DEFAULTBINARY 808 // Object
#define UA_NS0ID_DATACHANGENOTIFICATION 809 // DataType
#define UA_NS0ID_DATACHANGENOTIFICATION_ENCODING_DEFAULTXML 810 // Object
#define UA_NS0ID_DATACHANGENOTIFICATION_ENCODING_DEFAULTBINARY 811 // Object
#define UA_NS0ID_STATUSCHANGENOTIFICATION 818 // DataType
#define UA_NS0ID_STATUSCHANGENOTIFICATION_ENCODING_DEFAULTXML 819 // Object
#define UA_NS0ID_STATUSCHANGENOTIFICATION_ENCODING_DEFAULTBINARY 820 // Object
#define UA_NS0ID_SUBSCRIPTIONACKNOWLEDGEMENT 821 // DataType
#define UA_NS0ID_SUBSCRIPTIONACKNOWLEDGEMENT_ENCODING_DEFAULTXML 822 // Object
#define UA_NS0ID_SUBSCRIPTIONACKNOWLEDGEMENT_ENCODING_DEFAULTBINARY 823 // Object
#define UA_NS0ID_PUBLISHREQUEST 824 // DataType
#define UA_NS0ID_PUBLISHREQUEST_ENCODING_DEFAULTXML 825 // Object
#define UA_NS0ID_PUBLISHREQUEST_ENCODING_DEFAULTBINARY 826 // Object
#define UA_NS0ID_PUBLISHRESPONSE 827 // DataType
#define UA_NS0ID_PUBLISHRESPONSE_ENCODING_DEFAULTXML 828 // Object
#define UA_NS0ID_PUBLISHRESPONSE_ENCODING_DEFAULTBINARY 829 // Object
#define UA_NS0ID_REPUBLISHREQUEST 830 // DataType
#define UA_NS0ID_REPUBLISHREQUEST_ENCODING_DEFAULTXML 831 // Object
#define UA_NS0ID_REPUBLISHREQUEST_ENCODING_DEFAULTBINARY 832 // Object
#define UA_NS0ID_REPUBLISHRESPONSE 833 // DataType
#define UA_NS0ID_REPUBLISHRESPONSE_ENCODING_DEFAULTXML 834 // Object
#define UA_NS0ID_REPUBLISHRESPONSE_ENCODING_DEFAULTBINARY 835 // Object
#define UA_NS0ID_TRANSFERRESULT 836 // DataType
#define UA_NS0ID_TRANSFERRESULT_ENCODING_DEFAULTXML 837 // Object
#define UA_NS0ID_TRANSFERRESULT_ENCODING_DEFAULTBINARY 838 // Object
#define UA_NS0ID_TRANSFERSUBSCRIPTIONSREQUEST 839 // DataType
#define UA_NS0ID_TRANSFERSUBSCRIPTIONSREQUEST_ENCODING_DEFAULTXML 840 // Object
#define UA_NS0ID_TRANSFERSUBSCRIPTIONSREQUEST_ENCODING_DEFAULTBINARY 841 // Object
#define UA_NS0ID_TRANSFERSUBSCRIPTIONSRESPONSE 842 // DataType
#define UA_NS0ID_TRANSFERSUBSCRIPTIONSRESPONSE_ENCODING_DEFAULTXML 843 // Object
#define UA_NS0ID_TRANSFERSUBSCRIPTIONSRESPONSE_ENCODING_DEFAULTBINARY 844 // Object
#define UA_NS0ID_DELETESUBSCRIPTIONSREQUEST 845 // DataType
#define UA_NS0ID_DELETESUBSCRIPTIONSREQUEST_ENCODING_DEFAULTXML 846 // Object
#define UA_NS0ID_DELETESUBSCRIPTIONSREQUEST_ENCODING_DEFAULTBINARY 847 // Object
#define UA_NS0ID_DELETESUBSCRIPTIONSRESPONSE 848 // DataType
#define UA_NS0ID_DELETESUBSCRIPTIONSRESPONSE_ENCODING_DEFAULTXML 849 // Object
#define UA_NS0ID_DELETESUBSCRIPTIONSRESPONSE_ENCODING_DEFAULTBINARY 850 // Object
#define UA_NS0ID_REDUNDANCYSUPPORT 851 // DataType
#define UA_NS0ID_SERVERSTATE 852 // DataType
#define UA_NS0ID_REDUNDANTSERVERDATATYPE 853 // DataType
#define UA_NS0ID_SAMPLINGINTERVALDIAGNOSTICSDATATYPE 856 // DataType
#define UA_NS0ID_SERVERDIAGNOSTICSSUMMARYDATATYPE 859 // DataType
#define UA_NS0ID_SERVERSTATUSDATATYPE 862 // DataType
#define UA_NS0ID_SESSIONDIAGNOSTICSDATATYPE 865 // DataType
#define UA_NS0ID_SESSIONSECURITYDIAGNOSTICSDATATYPE 868 // DataType
#define UA_NS0ID_SERVICECOUNTERDATATYPE 871 // DataType
#define UA_NS0ID_SUBSCRIPTIONDIAGNOSTICSDATATYPE 874 // DataType
#define UA_NS0ID_MODELCHANGESTRUCTUREDATATYPE 877 // DataType
#define UA_NS0ID_RANGE 884 // DataType
#define UA_NS0ID_RANGE_ENCODING_DEFAULTXML 885 // Object
#define UA_NS0ID_RANGE_ENCODING_DEFAULTBINARY 886 // Object
#define UA_NS0ID_EUINFORMATION 887 // DataType
#define UA_NS0ID_EUINFORMATION_ENCODING_DEFAULTXML 888 // Object
#define UA_NS0ID_EUINFORMATION_ENCODING_DEFAULTBINARY 889 // Object
#define UA_NS0ID_EXCEPTIONDEVIATIONFORMAT 890 // DataType
#define UA_NS0ID_ANNOTATION 891 // DataType
#define UA_NS0ID_ANNOTATION_ENCODING_DEFAULTXML 892 // Object
#define UA_NS0ID_ANNOTATION_ENCODING_DEFAULTBINARY 893 // Object
#define UA_NS0ID_PROGRAMDIAGNOSTICDATATYPE 894 // DataType
#define UA_NS0ID_SEMANTICCHANGESTRUCTUREDATATYPE 897 // DataType
#define UA_NS0ID_EVENTNOTIFICATIONLIST 914 // DataType
#define UA_NS0ID_EVENTNOTIFICATIONLIST_ENCODING_DEFAULTXML 915 // Object
#define UA_NS0ID_EVENTNOTIFICATIONLIST_ENCODING_DEFAULTBINARY 916 // Object
#define UA_NS0ID_EVENTFIELDLIST 917 // DataType
#define UA_NS0ID_EVENTFIELDLIST_ENCODING_DEFAULTXML 918 // Object
#define UA_NS0ID_EVENTFIELDLIST_ENCODING_DEFAULTBINARY 919 // Object
#define UA_NS0ID_HISTORYEVENTFIELDLIST 920 // DataType
#define UA_NS0ID_HISTORYEVENTFIELDLIST_ENCODING_DEFAULTXML 921 // Object
#define UA_NS0ID_HISTORYEVENTFIELDLIST_ENCODING_DEFAULTBINARY 922 // Object
#define UA_NS0ID_ISSUEDIDENTITYTOKEN 938 // DataType
#define UA_NS0ID_ISSUEDIDENTITYTOKEN_ENCODING_DEFAULTXML 939 // Object
#define UA_NS0ID_ISSUEDIDENTITYTOKEN_ENCODING_DEFAULTBINARY 940 // Object
#define UA_NS0ID_NOTIFICATIONDATA 945 // DataType
#define UA_NS0ID_NOTIFICATIONDATA_ENCODING_DEFAULTXML 946 // Object
#define UA_NS0ID_NOTIFICATIONDATA_ENCODING_DEFAULTBINARY 947 // Object
#define UA_NS0ID_AGGREGATECONFIGURATION 948 // DataType
#define UA_NS0ID_AGGREGATECONFIGURATION_ENCODING_DEFAULTXML 949 // Object
#define UA_NS0ID_AGGREGATECONFIGURATION_ENCODING_DEFAULTBINARY 950 // Object
#define UA_NS0ID_IMAGEBMP 2000 // DataType
#define UA_NS0ID_IMAGEGIF 2001 // DataType
#define UA_NS0ID_IMAGEJPG 2002 // DataType
#define UA_NS0ID_IMAGEPNG 2003 // DataType
#define UA_NS0ID_SERVERTYPE 2004 // ObjectType
#define UA_NS0ID_SERVERCAPABILITIESTYPE 2013 // ObjectType
#define UA_NS0ID_SERVERDIAGNOSTICSTYPE 2020 // ObjectType
#define UA_NS0ID_SESSIONSDIAGNOSTICSSUMMARYTYPE 2026 // ObjectType
#define UA_NS0ID_SESSIONDIAGNOSTICSOBJECTTYPE 2029 // ObjectType
#define UA_NS0ID_VENDORSERVERINFOTYPE 2033 // ObjectType
#define UA_NS0ID_SERVERREDUNDANCYTYPE 2034 // ObjectType
#define UA_NS0ID_TRANSPARENTREDUNDANCYTYPE 2036 // ObjectType
#define UA_NS0ID_NONTRANSPARENTREDUNDANCYTYPE 2039 // ObjectType
#define UA_NS0ID_BASEEVENTTYPE 2041 // ObjectType
#define UA_NS0ID_AUDITEVENTTYPE 2052 // ObjectType
#define UA_NS0ID_AUDITSECURITYEVENTTYPE 2058 // ObjectType
#define UA_NS0ID_AUDITCHANNELEVENTTYPE 2059 // ObjectType
#define UA_NS0ID_AUDITOPENSECURECHANNELEVENTTYPE 2060 // ObjectType
#define UA_NS0ID_AUDITSESSIONEVENTTYPE 2069 // ObjectType
#define UA_NS0ID_AUDITCREATESESSIONEVENTTYPE 2071 // ObjectType
#define UA_NS0ID_AUDITACTIVATESESSIONEVENTTYPE 2075 // ObjectType
#define UA_NS0ID_AUDITCANCELEVENTTYPE 2078 // ObjectType
#define UA_NS0ID_AUDITCERTIFICATEEVENTTYPE 2080 // ObjectType
#define UA_NS0ID_AUDITCERTIFICATEDATAMISMATCHEVENTTYPE 2082 // ObjectType
#define UA_NS0ID_AUDITCERTIFICATEEXPIREDEVENTTYPE 2085 // ObjectType
#define UA_NS0ID_AUDITCERTIFICATEINVALIDEVENTTYPE 2086 // ObjectType
#define UA_NS0ID_AUDITCERTIFICATEUNTRUSTEDEVENTTYPE 2087 // ObjectType
#define UA_NS0ID_AUDITCERTIFICATEREVOKEDEVENTTYPE 2088 // ObjectType
#define UA_NS0ID_AUDITCERTIFICATEMISMATCHEVENTTYPE 2089 // ObjectType
#define UA_NS0ID_AUDITNODEMANAGEMENTEVENTTYPE 2090 // ObjectType
#define UA_NS0ID_AUDITADDNODESEVENTTYPE 2091 // ObjectType
#define UA_NS0ID_AUDITDELETENODESEVENTTYPE 2093 // ObjectType
#define UA_NS0ID_AUDITADDREFERENCESEVENTTYPE 2095 // ObjectType
#define UA_NS0ID_AUDITDELETEREFERENCESEVENTTYPE 2097 // ObjectType
#define UA_NS0ID_AUDITUPDATEEVENTTYPE 2099 // ObjectType
#define UA_NS0ID_AUDITWRITEUPDATEEVENTTYPE 2100 // ObjectType
#define UA_NS0ID_AUDITHISTORYUPDATEEVENTTYPE 2104 // ObjectType
#define UA_NS0ID_AUDITUPDATEMETHODEVENTTYPE 2127 // ObjectType
#define UA_NS0ID_SYSTEMEVENTTYPE 2130 // ObjectType
#define UA_NS0ID_DEVICEFAILUREEVENTTYPE 2131 // ObjectType
#define UA_NS0ID_BASEMODELCHANGEEVENTTYPE 2132 // ObjectType
#define UA_NS0ID_GENERALMODELCHANGEEVENTTYPE 2133 // ObjectType
#define UA_NS0ID_SERVERVENDORCAPABILITYTYPE 2137 // VariableType
#define UA_NS0ID_SERVERSTATUSTYPE 2138 // VariableType
#define UA_NS0ID_SERVERDIAGNOSTICSSUMMARYTYPE 2150 // VariableType
#define UA_NS0ID_SAMPLINGINTERVALDIAGNOSTICSARRAYTYPE 2164 // VariableType
#define UA_NS0ID_SAMPLINGINTERVALDIAGNOSTICSTYPE 2165 // VariableType
#define UA_NS0ID_SUBSCRIPTIONDIAGNOSTICSARRAYTYPE 2171 // VariableType
#define UA_NS0ID_SUBSCRIPTIONDIAGNOSTICSTYPE 2172 // VariableType
#define UA_NS0ID_SESSIONDIAGNOSTICSARRAYTYPE 2196 // VariableType
#define UA_NS0ID_SESSIONDIAGNOSTICSVARIABLETYPE 2197 // VariableType
#define UA_NS0ID_SESSIONSECURITYDIAGNOSTICSARRAYTYPE 2243 // VariableType
#define UA_NS0ID_SESSIONSECURITYDIAGNOSTICSTYPE 2244 // VariableType
#define UA_NS0ID_SERVER 2253 // Object
#define UA_NS0ID_SERVER_SERVERARRAY 2254 // Variable
#define UA_NS0ID_SERVER_NAMESPACEARRAY 2255 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS 2256 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_STARTTIME 2257 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_CURRENTTIME 2258 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_STATE 2259 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO 2260 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO_PRODUCTNAME 2261 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO_PRODUCTURI 2262 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO_MANUFACTURERNAME 2263 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO_SOFTWAREVERSION 2264 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO_BUILDNUMBER 2265 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_BUILDINFO_BUILDDATE 2266 // Variable
#define UA_NS0ID_SERVER_SERVICELEVEL 2267 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES 2268 // Object
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_SERVERPROFILEARRAY 2269 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_LOCALEIDARRAY 2271 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_MINSUPPORTEDSAMPLERATE 2272 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS 2274 // Object
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY 2275 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SERVERVIEWCOUNT 2276 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_CURRENTSESSIONCOUNT 2277 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_CUMULATEDSESSIONCOUNT 2278 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SECURITYREJECTEDSESSIONCOUNT 2279 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SESSIONTIMEOUTCOUNT 2281 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SESSIONABORTCOUNT 2282 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_PUBLISHINGINTERVALCOUNT 2284 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_CURRENTSUBSCRIPTIONCOUNT 2285 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_CUMULATEDSUBSCRIPTIONCOUNT 2286 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_SECURITYREJECTEDREQUESTSCOUNT 2287 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_REJECTEDREQUESTSCOUNT 2288 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SAMPLINGINTERVALDIAGNOSTICSARRAY 2289 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SUBSCRIPTIONDIAGNOSTICSARRAY 2290 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_ENABLEDFLAG 2294 // Variable
#define UA_NS0ID_SERVER_VENDORSERVERINFO 2295 // Object
#define UA_NS0ID_SERVER_SERVERREDUNDANCY 2296 // Object
#define UA_NS0ID_STATEMACHINETYPE 2299 // ObjectType
#define UA_NS0ID_STATETYPE 2307 // ObjectType
#define UA_NS0ID_INITIALSTATETYPE 2309 // ObjectType
#define UA_NS0ID_TRANSITIONTYPE 2310 // ObjectType
#define UA_NS0ID_TRANSITIONEVENTTYPE 2311 // ObjectType
#define UA_NS0ID_AUDITUPDATESTATEEVENTTYPE 2315 // ObjectType
#define UA_NS0ID_HISTORICALDATACONFIGURATIONTYPE 2318 // ObjectType
#define UA_NS0ID_HISTORYSERVERCAPABILITIESTYPE 2330 // ObjectType
#define UA_NS0ID_AGGREGATEFUNCTIONTYPE 2340 // ObjectType
#define UA_NS0ID_AGGREGATEFUNCTION_INTERPOLATIVE 2341 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_AVERAGE 2342 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_TIMEAVERAGE 2343 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_TOTAL 2344 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_MINIMUM 2346 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_MAXIMUM 2347 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_MINIMUMACTUALTIME 2348 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_MAXIMUMACTUALTIME 2349 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_RANGE 2350 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_ANNOTATIONCOUNT 2351 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_COUNT 2352 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_NUMBEROFTRANSITIONS 2355 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_START 2357 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_END 2358 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_DELTA 2359 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_DURATIONGOOD 2360 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_DURATIONBAD 2361 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_PERCENTGOOD 2362 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_PERCENTBAD 2363 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_WORSTQUALITY 2364 // Object
#define UA_NS0ID_DATAITEMTYPE 2365 // VariableType
#define UA_NS0ID_ANALOGITEMTYPE 2368 // VariableType
#define UA_NS0ID_DISCRETEITEMTYPE 2372 // VariableType
#define UA_NS0ID_TWOSTATEDISCRETETYPE 2373 // VariableType
#define UA_NS0ID_MULTISTATEDISCRETETYPE 2376 // VariableType
#define UA_NS0ID_PROGRAMTRANSITIONEVENTTYPE 2378 // ObjectType
#define UA_NS0ID_PROGRAMDIAGNOSTICTYPE 2380 // VariableType
#define UA_NS0ID_PROGRAMSTATEMACHINETYPE 2391 // ObjectType
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_MAXBROWSECONTINUATIONPOINTS 2735 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_MAXQUERYCONTINUATIONPOINTS 2736 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_MAXHISTORYCONTINUATIONPOINTS 2737 // Variable
#define UA_NS0ID_SEMANTICCHANGEEVENTTYPE 2738 // ObjectType
#define UA_NS0ID_AUDITURLMISMATCHEVENTTYPE 2748 // ObjectType
#define UA_NS0ID_STATEVARIABLETYPE 2755 // VariableType
#define UA_NS0ID_FINITESTATEVARIABLETYPE 2760 // VariableType
#define UA_NS0ID_TRANSITIONVARIABLETYPE 2762 // VariableType
#define UA_NS0ID_FINITETRANSITIONVARIABLETYPE 2767 // VariableType
#define UA_NS0ID_FINITESTATEMACHINETYPE 2771 // ObjectType
#define UA_NS0ID_CONDITIONTYPE 2782 // ObjectType
#define UA_NS0ID_REFRESHSTARTEVENTTYPE 2787 // ObjectType
#define UA_NS0ID_REFRESHENDEVENTTYPE 2788 // ObjectType
#define UA_NS0ID_REFRESHREQUIREDEVENTTYPE 2789 // ObjectType
#define UA_NS0ID_AUDITCONDITIONEVENTTYPE 2790 // ObjectType
#define UA_NS0ID_AUDITCONDITIONENABLEEVENTTYPE 2803 // ObjectType
#define UA_NS0ID_AUDITCONDITIONCOMMENTEVENTTYPE 2829 // ObjectType
#define UA_NS0ID_DIALOGCONDITIONTYPE 2830 // ObjectType
#define UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE 2881 // ObjectType
#define UA_NS0ID_ALARMCONDITIONTYPE 2915 // ObjectType
#define UA_NS0ID_SHELVEDSTATEMACHINETYPE 2929 // ObjectType
#define UA_NS0ID_LIMITALARMTYPE 2955 // ObjectType
#define UA_NS0ID_SERVER_SERVERSTATUS_SECONDSTILLSHUTDOWN 2992 // Variable
#define UA_NS0ID_SERVER_SERVERSTATUS_SHUTDOWNREASON 2993 // Variable
#define UA_NS0ID_SERVER_AUDITING 2994 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_MODELLINGRULES 2996 // Object
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_AGGREGATEFUNCTIONS 2997 // Object
#define UA_NS0ID_AUDITHISTORYEVENTUPDATEEVENTTYPE 2999 // ObjectType
#define UA_NS0ID_AUDITHISTORYVALUEUPDATEEVENTTYPE 3006 // ObjectType
#define UA_NS0ID_AUDITHISTORYDELETEEVENTTYPE 3012 // ObjectType
#define UA_NS0ID_AUDITHISTORYRAWMODIFYDELETEEVENTTYPE 3014 // ObjectType
#define UA_NS0ID_AUDITHISTORYATTIMEDELETEEVENTTYPE 3019 // ObjectType
#define UA_NS0ID_AUDITHISTORYEVENTDELETEEVENTTYPE 3022 // ObjectType
#define UA_NS0ID_EVENTQUEUEOVERFLOWEVENTTYPE 3035 // ObjectType
#define UA_NS0ID_EVENTTYPESFOLDER 3048 // Object
#define UA_NS0ID_BUILDINFOTYPE 3051 // VariableType
#define UA_NS0ID_DEFAULTBINARY 3062 // Object
#define UA_NS0ID_DEFAULTXML 3063 // Object
#define UA_NS0ID_ALWAYSGENERATESEVENT 3065 // ReferenceType
#define UA_NS0ID_ICON 3067 // Variable
#define UA_NS0ID_NODEVERSION 3068 // Variable
#define UA_NS0ID_LOCALTIME 3069 // Variable
#define UA_NS0ID_ALLOWNULLS 3070 // Variable
#define UA_NS0ID_ENUMVALUES 3071 // Variable
#define UA_NS0ID_INPUTARGUMENTS 3072 // Variable
#define UA_NS0ID_OUTPUTARGUMENTS 3073 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_SOFTWARECERTIFICATES 3704 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SERVERDIAGNOSTICSSUMMARY_REJECTEDSESSIONCOUNT 3705 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SESSIONSDIAGNOSTICSSUMMARY 3706 // Object
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SESSIONSDIAGNOSTICSSUMMARY_SESSIONDIAGNOSTICSARRAY 3707 // Variable
#define UA_NS0ID_SERVER_SERVERDIAGNOSTICS_SESSIONSDIAGNOSTICSSUMMARY_SESSIONSECURITYDIAGNOSTICSARRAY 3708 // Variable
#define UA_NS0ID_SERVER_SERVERREDUNDANCY_REDUNDANCYSUPPORT 3709 // Variable
#define UA_NS0ID_PROGRAMTRANSITIONAUDITEVENTTYPE 3806 // ObjectType
#define UA_NS0ID_ADDCOMMENTMETHODTYPE 3863 // Method
#define UA_NS0ID_TIMEDSHELVEMETHODTYPE 6102 // Method
#define UA_NS0ID_ENUMVALUETYPE 7594 // DataType
#define UA_NS0ID_MESSAGESECURITYMODE_ENUMSTRINGS 7595 // Variable
#define UA_NS0ID_BROWSEDIRECTION_ENUMSTRINGS 7603 // Variable
#define UA_NS0ID_FILTEROPERATOR_ENUMSTRINGS 7605 // Variable
#define UA_NS0ID_TIMESTAMPSTORETURN_ENUMSTRINGS 7606 // Variable
#define UA_NS0ID_MONITORINGMODE_ENUMSTRINGS 7608 // Variable
#define UA_NS0ID_DATACHANGETRIGGER_ENUMSTRINGS 7609 // Variable
#define UA_NS0ID_REDUNDANCYSUPPORT_ENUMSTRINGS 7611 // Variable
#define UA_NS0ID_SERVERSTATE_ENUMSTRINGS 7612 // Variable
#define UA_NS0ID_EXCEPTIONDEVIATIONFORMAT_ENUMSTRINGS 7614 // Variable
#define UA_NS0ID_TIMEZONEDATATYPE 8912 // DataType
#define UA_NS0ID_AUDITCONDITIONRESPONDEVENTTYPE 8927 // ObjectType
#define UA_NS0ID_AUDITCONDITIONACKNOWLEDGEEVENTTYPE 8944 // ObjectType
#define UA_NS0ID_AUDITCONDITIONCONFIRMEVENTTYPE 8961 // ObjectType
#define UA_NS0ID_TWOSTATEVARIABLETYPE 8995 // VariableType
#define UA_NS0ID_CONDITIONVARIABLETYPE 9002 // VariableType
#define UA_NS0ID_HASTRUESUBSTATE 9004 // ReferenceType
#define UA_NS0ID_HASFALSESUBSTATE 9005 // ReferenceType
#define UA_NS0ID_HASCONDITION 9006 // ReferenceType
#define UA_NS0ID_CONDITIONREFRESHMETHODTYPE 9007 // Method
#define UA_NS0ID_DIALOGRESPONSEMETHODTYPE 9031 // Method
#define UA_NS0ID_EXCLUSIVELIMITSTATEMACHINETYPE 9318 // ObjectType
#define UA_NS0ID_EXCLUSIVELIMITALARMTYPE 9341 // ObjectType
#define UA_NS0ID_EXCLUSIVELEVELALARMTYPE 9482 // ObjectType
#define UA_NS0ID_EXCLUSIVERATEOFCHANGEALARMTYPE 9623 // ObjectType
#define UA_NS0ID_EXCLUSIVEDEVIATIONALARMTYPE 9764 // ObjectType
#define UA_NS0ID_NONEXCLUSIVELIMITALARMTYPE 9906 // ObjectType
#define UA_NS0ID_NONEXCLUSIVELEVELALARMTYPE 10060 // ObjectType
#define UA_NS0ID_NONEXCLUSIVERATEOFCHANGEALARMTYPE 10214 // ObjectType
#define UA_NS0ID_NONEXCLUSIVEDEVIATIONALARMTYPE 10368 // ObjectType
#define UA_NS0ID_DISCRETEALARMTYPE 10523 // ObjectType
#define UA_NS0ID_OFFNORMALALARMTYPE 10637 // ObjectType
#define UA_NS0ID_TRIPALARMTYPE 10751 // ObjectType
#define UA_NS0ID_AUDITCONDITIONSHELVINGEVENTTYPE 11093 // ObjectType
#define UA_NS0ID_BASECONDITIONCLASSTYPE 11163 // ObjectType
#define UA_NS0ID_PROCESSCONDITIONCLASSTYPE 11164 // ObjectType
#define UA_NS0ID_MAINTENANCECONDITIONCLASSTYPE 11165 // ObjectType
#define UA_NS0ID_SYSTEMCONDITIONCLASSTYPE 11166 // ObjectType
#define UA_NS0ID_AGGREGATECONFIGURATIONTYPE 11187 // ObjectType
#define UA_NS0ID_HISTORYSERVERCAPABILITIES 11192 // Object
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_ACCESSHISTORYDATACAPABILITY 11193 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_INSERTDATACAPABILITY 11196 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_REPLACEDATACAPABILITY 11197 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_UPDATEDATACAPABILITY 11198 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_DELETERAWCAPABILITY 11199 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_DELETEATTIMECAPABILITY 11200 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_AGGREGATEFUNCTIONS 11201 // Object
#define UA_NS0ID_HACONFIGURATION 11202 // Object
#define UA_NS0ID_HACONFIGURATION_AGGREGATECONFIGURATION 11203 // Object
#define UA_NS0ID_HACONFIGURATION_AGGREGATECONFIGURATION_TREATUNCERTAINASBAD 11204 // Variable
#define UA_NS0ID_HACONFIGURATION_AGGREGATECONFIGURATION_PERCENTDATABAD 11205 // Variable
#define UA_NS0ID_HACONFIGURATION_AGGREGATECONFIGURATION_PERCENTDATAGOOD 11206 // Variable
#define UA_NS0ID_HACONFIGURATION_AGGREGATECONFIGURATION_USESLOPEDEXTRAPOLATION 11207 // Variable
#define UA_NS0ID_HACONFIGURATION_STEPPED 11208 // Variable
#define UA_NS0ID_HACONFIGURATION_DEFINITION 11209 // Variable
#define UA_NS0ID_HACONFIGURATION_MAXTIMEINTERVAL 11210 // Variable
#define UA_NS0ID_HACONFIGURATION_MINTIMEINTERVAL 11211 // Variable
#define UA_NS0ID_HACONFIGURATION_EXCEPTIONDEVIATION 11212 // Variable
#define UA_NS0ID_HACONFIGURATION_EXCEPTIONDEVIATIONFORMAT 11213 // Variable
#define UA_NS0ID_ANNOTATIONS 11214 // Variable
#define UA_NS0ID_HISTORICALEVENTFILTER 11215 // Variable
#define UA_NS0ID_MODIFICATIONINFO 11216 // DataType
#define UA_NS0ID_HISTORYMODIFIEDDATA 11217 // DataType
#define UA_NS0ID_MODIFICATIONINFO_ENCODING_DEFAULTXML 11218 // Object
#define UA_NS0ID_HISTORYMODIFIEDDATA_ENCODING_DEFAULTXML 11219 // Object
#define UA_NS0ID_MODIFICATIONINFO_ENCODING_DEFAULTBINARY 11226 // Object
#define UA_NS0ID_HISTORYMODIFIEDDATA_ENCODING_DEFAULTBINARY 11227 // Object
#define UA_NS0ID_HISTORYUPDATETYPE 11234 // DataType
#define UA_NS0ID_MULTISTATEVALUEDISCRETETYPE 11238 // VariableType
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_ACCESSHISTORYEVENTSCAPABILITY 11242 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_MAXRETURNDATAVALUES 11273 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_MAXRETURNEVENTVALUES 11274 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_INSERTANNOTATIONCAPABILITY 11275 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_INSERTEVENTCAPABILITY 11281 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_REPLACEEVENTCAPABILITY 11282 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_UPDATEEVENTCAPABILITY 11283 // Variable
#define UA_NS0ID_AGGREGATEFUNCTION_TIMEAVERAGE2 11285 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_MINIMUM2 11286 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_MAXIMUM2 11287 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_RANGE2 11288 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_WORSTQUALITY2 11292 // Object
#define UA_NS0ID_PERFORMUPDATETYPE 11293 // DataType
#define UA_NS0ID_UPDATESTRUCTUREDATADETAILS 11295 // DataType
#define UA_NS0ID_UPDATESTRUCTUREDATADETAILS_ENCODING_DEFAULTXML 11296 // Object
#define UA_NS0ID_UPDATESTRUCTUREDATADETAILS_ENCODING_DEFAULTBINARY 11300 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_TOTAL2 11304 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_MINIMUMACTUALTIME2 11305 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_MAXIMUMACTUALTIME2 11306 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_DURATIONINSTATEZERO 11307 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_DURATIONINSTATENONZERO 11308 // Object
#define UA_NS0ID_SERVER_SERVERREDUNDANCY_CURRENTSERVERID 11312 // Variable
#define UA_NS0ID_SERVER_SERVERREDUNDANCY_REDUNDANTSERVERARRAY 11313 // Variable
#define UA_NS0ID_SERVER_SERVERREDUNDANCY_SERVERURIARRAY 11314 // Variable
#define UA_NS0ID_AGGREGATEFUNCTION_STANDARDDEVIATIONSAMPLE 11426 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_STANDARDDEVIATIONPOPULATION 11427 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_VARIANCESAMPLE 11428 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_VARIANCEPOPULATION 11429 // Object
#define UA_NS0ID_ENUMSTRINGS 11432 // Variable
#define UA_NS0ID_VALUEASTEXT 11433 // Variable
#define UA_NS0ID_PROGRESSEVENTTYPE 11436 // ObjectType
#define UA_NS0ID_SYSTEMSTATUSCHANGEEVENTTYPE 11446 // ObjectType
#define UA_NS0ID_OPTIONSETTYPE 11487 // VariableType
#define UA_NS0ID_SERVER_GETMONITOREDITEMS 11492 // Method
#define UA_NS0ID_SERVER_GETMONITOREDITEMS_INPUTARGUMENTS 11493 // Variable
#define UA_NS0ID_SERVER_GETMONITOREDITEMS_OUTPUTARGUMENTS 11494 // Variable
#define UA_NS0ID_GETMONITOREDITEMSMETHODTYPE 11495 // Method
#define UA_NS0ID_MAXSTRINGLENGTH 11498 // Variable
#define UA_NS0ID_HISTORYSERVERCAPABILITIES_DELETEEVENTCAPABILITY 11502 // Variable
#define UA_NS0ID_HACONFIGURATION_STARTOFARCHIVE 11503 // Variable
#define UA_NS0ID_HACONFIGURATION_STARTOFONLINEARCHIVE 11504 // Variable
#define UA_NS0ID_AGGREGATEFUNCTION_STARTBOUND 11505 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_ENDBOUND 11506 // Object
#define UA_NS0ID_AGGREGATEFUNCTION_DELTABOUNDS 11507 // Object
#define UA_NS0ID_MODELLINGRULE_OPTIONALPLACEHOLDER 11508 // Object
#define UA_NS0ID_MODELLINGRULE_OPTIONALPLACEHOLDER_NAMINGRULE 11509 // Variable
#define UA_NS0ID_MODELLINGRULE_MANDATORYPLACEHOLDER 11510 // Object
#define UA_NS0ID_MODELLINGRULE_MANDATORYPLACEHOLDER_NAMINGRULE 11511 // Variable
#define UA_NS0ID_MAXARRAYLENGTH 11512 // Variable
#define UA_NS0ID_ENGINEERINGUNITS 11513 // Variable
#define UA_NS0ID_OPERATIONLIMITSTYPE 11564 // ObjectType
#define UA_NS0ID_FILETYPE 11575 // ObjectType
#define UA_NS0ID_ADDRESSSPACEFILETYPE 11595 // ObjectType
#define UA_NS0ID_NAMESPACEMETADATATYPE 11616 // ObjectType
#define UA_NS0ID_NAMESPACESTYPE 11645 // ObjectType
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_MAXARRAYLENGTH 11702 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_MAXSTRINGLENGTH 11703 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS 11704 // Object
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERREAD 11705 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERWRITE 11707 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERMETHODCALL 11709 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERBROWSE 11710 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERREGISTERNODES 11711 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERTRANSLATEBROWSEPATHSTONODEIDS 11712 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERNODEMANAGEMENT 11713 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXMONITOREDITEMSPERCALL 11714 // Variable
#define UA_NS0ID_SERVER_NAMESPACES 11715 // Object
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE 11716 // Object
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_SIZE 11717 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_OPENCOUNT 11720 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_OPEN 11721 // Method
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_OPEN_INPUTARGUMENTS 11722 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_OPEN_OUTPUTARGUMENTS 11723 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_CLOSE 11724 // Method
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_CLOSE_INPUTARGUMENTS 11725 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_READ 11726 // Method
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_READ_INPUTARGUMENTS 11727 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_READ_OUTPUTARGUMENTS 11728 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_WRITE 11729 // Method
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_WRITE_INPUTARGUMENTS 11730 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_GETPOSITION 11731 // Method
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_GETPOSITION_INPUTARGUMENTS 11732 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_GETPOSITION_OUTPUTARGUMENTS 11733 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_SETPOSITION 11734 // Method
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_SETPOSITION_INPUTARGUMENTS 11735 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_EXPORTNAMESPACE 11736 // Method
#define UA_NS0ID_BITFIELDMASKDATATYPE 11737 // DataType
#define UA_NS0ID_OPENMETHODTYPE 11738 // Method
#define UA_NS0ID_CLOSEMETHODTYPE 11741 // Method
#define UA_NS0ID_READMETHODTYPE 11743 // Method
#define UA_NS0ID_WRITEMETHODTYPE 11746 // Method
#define UA_NS0ID_GETPOSITIONMETHODTYPE 11748 // Method
#define UA_NS0ID_SETPOSITIONMETHODTYPE 11751 // Method
#define UA_NS0ID_SYSTEMOFFNORMALALARMTYPE 11753 // ObjectType
#define UA_NS0ID_AUDITPROGRAMTRANSITIONEVENTTYPE 11856 // ObjectType
#define UA_NS0ID_HACONFIGURATION_AGGREGATEFUNCTIONS 11877 // Object
#define UA_NS0ID_NODECLASS_ENUMVALUES 11878 // Variable
#define UA_NS0ID_INSTANCENODE 11879 // DataType
#define UA_NS0ID_TYPENODE 11880 // DataType
#define UA_NS0ID_NODEATTRIBUTESMASK_ENUMVALUES 11881 // Variable
#define UA_NS0ID_ATTRIBUTEWRITEMASK_ENUMVALUES 11882 // Variable
#define UA_NS0ID_BROWSERESULTMASK_ENUMVALUES 11883 // Variable
#define UA_NS0ID_INSTANCENODE_ENCODING_DEFAULTXML 11887 // Object
#define UA_NS0ID_TYPENODE_ENCODING_DEFAULTXML 11888 // Object
#define UA_NS0ID_INSTANCENODE_ENCODING_DEFAULTBINARY 11889 // Object
#define UA_NS0ID_TYPENODE_ENCODING_DEFAULTBINARY 11890 // Object
#define UA_NS0ID_OPENFILEMODE 11939 // DataType
#define UA_NS0ID_OPENFILEMODE_ENUMVALUES 11940 // Variable
#define UA_NS0ID_MODELCHANGESTRUCTUREVERBMASK 11941 // DataType
#define UA_NS0ID_MODELCHANGESTRUCTUREVERBMASK_ENUMVALUES 11942 // Variable
#define UA_NS0ID_ENDPOINTURLLISTDATATYPE 11943 // DataType
#define UA_NS0ID_NETWORKGROUPDATATYPE 11944 // DataType
#define UA_NS0ID_NONTRANSPARENTNETWORKREDUNDANCYTYPE 11945 // ObjectType
#define UA_NS0ID_ARRAYITEMTYPE 12021 // VariableType
#define UA_NS0ID_YARRAYITEMTYPE 12029 // VariableType
#define UA_NS0ID_XYARRAYITEMTYPE 12038 // VariableType
#define UA_NS0ID_IMAGEITEMTYPE 12047 // VariableType
#define UA_NS0ID_CUBEITEMTYPE 12057 // VariableType
#define UA_NS0ID_NDIMENSIONARRAYITEMTYPE 12068 // VariableType
#define UA_NS0ID_AXISSCALEENUMERATION 12077 // DataType
#define UA_NS0ID_AXISSCALEENUMERATION_ENUMSTRINGS 12078 // Variable
#define UA_NS0ID_AXISINFORMATION 12079 // DataType
#define UA_NS0ID_XVTYPE 12080 // DataType
#define UA_NS0ID_AXISINFORMATION_ENCODING_DEFAULTXML 12081 // Object
#define UA_NS0ID_AXISINFORMATION_ENCODING_DEFAULTBINARY 12089 // Object
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERHISTORYREADDATA 12165 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERHISTORYREADEVENTS 12166 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERHISTORYUPDATEDATA 12167 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_OPERATIONLIMITS_MAXNODESPERHISTORYUPDATEEVENTS 12168 // Variable
#define UA_NS0ID_VIEWVERSION 12170 // Variable
#define UA_NS0ID_COMPLEXNUMBERTYPE 12171 // DataType
#define UA_NS0ID_DOUBLECOMPLEXNUMBERTYPE 12172 // DataType
#define UA_NS0ID_SERVERONNETWORK 12189 // DataType
#define UA_NS0ID_FINDSERVERSONNETWORKREQUEST 12190 // DataType
#define UA_NS0ID_FINDSERVERSONNETWORKRESPONSE 12191 // DataType
#define UA_NS0ID_REGISTERSERVER2REQUEST 12193 // DataType
#define UA_NS0ID_REGISTERSERVER2RESPONSE 12194 // DataType
#define UA_NS0ID_SERVERONNETWORK_ENCODING_DEFAULTXML 12195 // Object
#define UA_NS0ID_FINDSERVERSONNETWORKREQUEST_ENCODING_DEFAULTXML 12196 // Object
#define UA_NS0ID_FINDSERVERSONNETWORKRESPONSE_ENCODING_DEFAULTXML 12197 // Object
#define UA_NS0ID_REGISTERSERVER2REQUEST_ENCODING_DEFAULTXML 12199 // Object
#define UA_NS0ID_REGISTERSERVER2RESPONSE_ENCODING_DEFAULTXML 12200 // Object
#define UA_NS0ID_SERVERONNETWORK_ENCODING_DEFAULTBINARY 12207 // Object
#define UA_NS0ID_FINDSERVERSONNETWORKREQUEST_ENCODING_DEFAULTBINARY 12208 // Object
#define UA_NS0ID_FINDSERVERSONNETWORKRESPONSE_ENCODING_DEFAULTBINARY 12209 // Object
#define UA_NS0ID_REGISTERSERVER2REQUEST_ENCODING_DEFAULTBINARY 12211 // Object
#define UA_NS0ID_REGISTERSERVER2RESPONSE_ENCODING_DEFAULTBINARY 12212 // Object
#define UA_NS0ID_OPENWITHMASKSMETHODTYPE 12513 // Method
#define UA_NS0ID_CLOSEANDUPDATEMETHODTYPE 12516 // Method
#define UA_NS0ID_ADDCERTIFICATEMETHODTYPE 12518 // Method
#define UA_NS0ID_REMOVECERTIFICATEMETHODTYPE 12520 // Method
#define UA_NS0ID_TRUSTLISTTYPE 12522 // ObjectType
#define UA_NS0ID_TRUSTLISTMASKS 12552 // DataType
#define UA_NS0ID_TRUSTLISTMASKS_ENUMVALUES 12553 // Variable
#define UA_NS0ID_TRUSTLISTDATATYPE 12554 // DataType
#define UA_NS0ID_CERTIFICATEGROUPTYPE 12555 // ObjectType
#define UA_NS0ID_CERTIFICATETYPE 12556 // ObjectType
#define UA_NS0ID_APPLICATIONCERTIFICATETYPE 12557 // ObjectType
#define UA_NS0ID_HTTPSCERTIFICATETYPE 12558 // ObjectType
#define UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE 12559 // ObjectType
#define UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE 12560 // ObjectType
#define UA_NS0ID_TRUSTLISTUPDATEDAUDITEVENTTYPE 12561 // ObjectType
#define UA_NS0ID_UPDATECERTIFICATEMETHODTYPE 12578 // Method
#define UA_NS0ID_SERVERCONFIGURATIONTYPE 12581 // ObjectType
#define UA_NS0ID_CERTIFICATEUPDATEDAUDITEVENTTYPE 12620 // ObjectType
#define UA_NS0ID_SERVERCONFIGURATION 12637 // Object
#define UA_NS0ID_SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS 12639 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_MAXTRUSTLISTSIZE 12640 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_MULTICASTDNSENABLED 12641 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST 12642 // Object
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_SIZE 12643 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPENCOUNT 12646 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN 12647 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN_INPUTARGUMENTS 12648 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPEN_OUTPUTARGUMENTS 12649 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE 12650 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSE_INPUTARGUMENTS 12651 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ 12652 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ_INPUTARGUMENTS 12653 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_READ_OUTPUTARGUMENTS 12654 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_WRITE 12655 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_WRITE_INPUTARGUMENTS 12656 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_GETPOSITION 12657 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_GETPOSITION_INPUTARGUMENTS 12658 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_GETPOSITION_OUTPUTARGUMENTS 12659 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_SETPOSITION 12660 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_SETPOSITION_INPUTARGUMENTS 12661 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_LASTUPDATETIME 12662 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPENWITHMASKS 12663 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPENWITHMASKS_INPUTARGUMENTS 12664 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_OPENWITHMASKS_OUTPUTARGUMENTS 12665 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSEANDUPDATE 12666 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSEANDUPDATE_OUTPUTARGUMENTS 12667 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_ADDCERTIFICATE 12668 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_ADDCERTIFICATE_INPUTARGUMENTS 12669 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_REMOVECERTIFICATE 12670 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_REMOVECERTIFICATE_INPUTARGUMENTS 12671 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_WRITABLE 12696 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_USERWRITABLE 12697 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_SERVERCAPABILITIES 12710 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST 12737 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST_INPUTARGUMENTS 12738 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST_OUTPUTARGUMENTS 12739 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES 12740 // Method
#define UA_NS0ID_CREATESIGNINGREQUESTMETHODTYPE 12741 // Method
#define UA_NS0ID_OPTIONSETVALUES 12745 // Variable
#define UA_NS0ID_SERVER_SETSUBSCRIPTIONDURABLE 12749 // Method
#define UA_NS0ID_SERVER_SETSUBSCRIPTIONDURABLE_INPUTARGUMENTS 12750 // Variable
#define UA_NS0ID_SERVER_SETSUBSCRIPTIONDURABLE_OUTPUTARGUMENTS 12751 // Variable
#define UA_NS0ID_SETSUBSCRIPTIONDURABLEMETHODTYPE 12752 // Method
#define UA_NS0ID_OPTIONSET 12755 // DataType
#define UA_NS0ID_UNION 12756 // DataType
#define UA_NS0ID_OPTIONSET_ENCODING_DEFAULTXML 12757 // Object
#define UA_NS0ID_UNION_ENCODING_DEFAULTXML 12758 // Object
#define UA_NS0ID_OPTIONSET_ENCODING_DEFAULTBINARY 12765 // Object
#define UA_NS0ID_UNION_ENCODING_DEFAULTBINARY 12766 // Object
#define UA_NS0ID_GETREJECTEDLISTMETHODTYPE 12773 // Method
#define UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST 12777 // Method
#define UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST_OUTPUTARGUMENTS 12778 // Variable
#define UA_NS0ID_SERVER_RESENDDATA 12873 // Method
#define UA_NS0ID_SERVER_RESENDDATA_INPUTARGUMENTS 12874 // Variable
#define UA_NS0ID_RESENDDATAMETHODTYPE 12875 // Method
#define UA_NS0ID_NORMALIZEDSTRING 12877 // DataType
#define UA_NS0ID_DECIMALSTRING 12878 // DataType
#define UA_NS0ID_DURATIONSTRING 12879 // DataType
#define UA_NS0ID_TIMESTRING 12880 // DataType
#define UA_NS0ID_DATESTRING 12881 // DataType
#define UA_NS0ID_SERVER_ESTIMATEDRETURNTIME 12885 // Variable
#define UA_NS0ID_SERVER_REQUESTSERVERSTATECHANGE 12886 // Method
#define UA_NS0ID_SERVER_REQUESTSERVERSTATECHANGE_INPUTARGUMENTS 12887 // Variable
#define UA_NS0ID_REQUESTSERVERSTATECHANGEMETHODTYPE 12888 // Method
#define UA_NS0ID_DISCOVERYCONFIGURATION 12890 // DataType
#define UA_NS0ID_MDNSDISCOVERYCONFIGURATION 12891 // DataType
#define UA_NS0ID_DISCOVERYCONFIGURATION_ENCODING_DEFAULTXML 12892 // Object
#define UA_NS0ID_MDNSDISCOVERYCONFIGURATION_ENCODING_DEFAULTXML 12893 // Object
#define UA_NS0ID_DISCOVERYCONFIGURATION_ENCODING_DEFAULTBINARY 12900 // Object
#define UA_NS0ID_MDNSDISCOVERYCONFIGURATION_ENCODING_DEFAULTBINARY 12901 // Object
#define UA_NS0ID_MAXBYTESTRINGLENGTH 12908 // Variable
#define UA_NS0ID_SERVER_SERVERCAPABILITIES_MAXBYTESTRINGLENGTH 12911 // Variable
#define UA_NS0ID_CONDITIONREFRESH2METHODTYPE 12914 // Method
#define UA_NS0ID_CERTIFICATEEXPIRATIONALARMTYPE 13225 // ObjectType
#define UA_NS0ID_CREATEDIRECTORYMETHODTYPE 13342 // Method
#define UA_NS0ID_CREATEFILEMETHODTYPE 13345 // Method
#define UA_NS0ID_DELETEFILEMETHODTYPE 13348 // Method
#define UA_NS0ID_MOVEORCOPYMETHODTYPE 13350 // Method
#define UA_NS0ID_FILEDIRECTORYTYPE 13353 // ObjectType
#define UA_NS0ID_SERVER_NAMESPACES_ADDRESSSPACEFILE_MIMETYPE 13402 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE 13737 // Method
#define UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE_INPUTARGUMENTS 13738 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE_OUTPUTARGUMENTS 13739 // Variable
#define UA_NS0ID_CERTIFICATEGROUPFOLDERTYPE 13813 // ObjectType
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS 14053 // Object
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP 14088 // Object
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST 14089 // Object
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_SIZE 14090 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_WRITABLE 14091 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_USERWRITABLE 14092 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_OPENCOUNT 14093 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_MIMETYPE 14094 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_OPEN 14095 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_OPEN_INPUTARGUMENTS 14096 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_OPEN_OUTPUTARGUMENTS 14097 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_CLOSE 14098 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_CLOSE_INPUTARGUMENTS 14099 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_READ 14100 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_READ_INPUTARGUMENTS 14101 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_READ_OUTPUTARGUMENTS 14102 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_WRITE 14103 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_WRITE_INPUTARGUMENTS 14104 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_GETPOSITION 14105 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_GETPOSITION_INPUTARGUMENTS 14106 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_GETPOSITION_OUTPUTARGUMENTS 14107 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_SETPOSITION 14108 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_SETPOSITION_INPUTARGUMENTS 14109 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_LASTUPDATETIME 14110 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_OPENWITHMASKS 14111 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_OPENWITHMASKS_INPUTARGUMENTS 14112 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_OPENWITHMASKS_OUTPUTARGUMENTS 14113 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_CLOSEANDUPDATE 14114 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_CLOSEANDUPDATE_INPUTARGUMENTS 14115 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_CLOSEANDUPDATE_OUTPUTARGUMENTS 14116 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_ADDCERTIFICATE 14117 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_ADDCERTIFICATE_INPUTARGUMENTS 14118 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_REMOVECERTIFICATE 14119 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_TRUSTLIST_REMOVECERTIFICATE_INPUTARGUMENTS 14120 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP_CERTIFICATETYPES 14121 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP 14122 // Object
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST 14123 // Object
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_SIZE 14124 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_WRITABLE 14125 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_USERWRITABLE 14126 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_OPENCOUNT 14127 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_MIMETYPE 14128 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_OPEN 14129 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_OPEN_INPUTARGUMENTS 14130 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_OPEN_OUTPUTARGUMENTS 14131 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_CLOSE 14132 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_CLOSE_INPUTARGUMENTS 14133 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_READ 14134 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_READ_INPUTARGUMENTS 14135 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_READ_OUTPUTARGUMENTS 14136 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_WRITE 14137 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_WRITE_INPUTARGUMENTS 14138 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_GETPOSITION 14139 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_GETPOSITION_INPUTARGUMENTS 14140 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_GETPOSITION_OUTPUTARGUMENTS 14141 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_SETPOSITION 14142 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_SETPOSITION_INPUTARGUMENTS 14143 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_LASTUPDATETIME 14144 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_OPENWITHMASKS 14145 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_OPENWITHMASKS_INPUTARGUMENTS 14146 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_OPENWITHMASKS_OUTPUTARGUMENTS 14147 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_CLOSEANDUPDATE 14148 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_CLOSEANDUPDATE_INPUTARGUMENTS 14149 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_CLOSEANDUPDATE_OUTPUTARGUMENTS 14150 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_ADDCERTIFICATE 14151 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_ADDCERTIFICATE_INPUTARGUMENTS 14152 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_REMOVECERTIFICATE 14153 // Method
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_TRUSTLIST_REMOVECERTIFICATE_INPUTARGUMENTS 14154 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP_CERTIFICATETYPES 14155 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP 14156 // Object
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_WRITABLE 14157 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_USERWRITABLE 14158 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_MIMETYPE 14159 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_TRUSTLIST_CLOSEANDUPDATE_INPUTARGUMENTS 14160 // Variable
#define UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES 14161 // Variable
#define UA_NS0ID_SERVER_SERVERREDUNDANCY_SERVERNETWORKGROUPS 14415 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI 15182 // Object
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEURI 15183 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEVERSION 15184 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEPUBLICATIONDATE 15185 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_ISNAMESPACESUBSET 15186 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_STATICNODEIDTYPES 15187 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_STATICNUMERICNODEIDRANGE 15188 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_STATICSTRINGNODEIDPATTERN 15189 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE 15190 // Object
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_SIZE 15191 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_WRITABLE 15192 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_USERWRITABLE 15193 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_OPENCOUNT 15194 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_MIMETYPE 15195 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_OPEN 15196 // Method
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_OPEN_INPUTARGUMENTS 15197 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_OPEN_OUTPUTARGUMENTS 15198 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_CLOSE 15199 // Method
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_CLOSE_INPUTARGUMENTS 15200 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_READ 15201 // Method
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_READ_INPUTARGUMENTS 15202 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_READ_OUTPUTARGUMENTS 15203 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_WRITE 15204 // Method
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_WRITE_INPUTARGUMENTS 15205 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_GETPOSITION 15206 // Method
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_GETPOSITION_INPUTARGUMENTS 15207 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_GETPOSITION_OUTPUTARGUMENTS 15208 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_SETPOSITION 15209 // Method
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_SETPOSITION_INPUTARGUMENTS 15210 // Variable
#define UA_NS0ID_SERVER_NAMESPACES_OPCUANAMESPACEURI_NAMESPACEFILE_EXPORTNAMESPACE 15211 // Method
#define UA_NS0ID_HASMODELPARENT 50 // ReferenceType

#define UA_VALUERANK_SCALAR_OR_ONE_DIMENSION  -3
#define UA_VALUERANK_ANY                      -2
#define UA_VALUERANK_SCALAR                   -1
#define UA_VALUERANK_ONE_OR_MORE_DIMENSIONS    0
#define UA_VALUERANK_ONE_DIMENSION             1
#define UA_VALUERANK_TWO_DIMENSIONS            2
#define UA_VALUERANK_THREE_DIMENSIONS          3

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_types.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2014 (c) Leon Urbas
 *    Copyright 2014, 2016-2017 (c) Florian Palm
 *    Copyright 2014-2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2015-2016 (c) Sten Grüner
 *    Copyright 2015-2016 (c) Chris Iatrou
 *    Copyright 2015 (c) Nick Goossens
 *    Copyright 2015-2016 (c) Oleksiy Vasylyev
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Thomas Stalder, Blue Time Concept SA
 */


#ifdef __cplusplus
extern "C" {
#endif


#define UA_BUILTIN_TYPES_COUNT 25U

/**
 * .. _types:
 *
 * Data Types
 * ==========
 *
 * The OPC UA protocol defines 25 builtin data types and three ways of combining
 * them into higher-order types: arrays, structures and unions. In open62541,
 * only the builtin data types are defined manually. All other data types are
 * generated from standard XML definitions. Their exact definitions can be
 * looked up at https://opcfoundation.org/UA/schemas/Opc.Ua.Types.bsd.xml.
 *
 * For users that are new to open62541, take a look at the :ref:`tutorial for
 * working with data types<types-tutorial>` before diving into the
 * implementation details.
 *
 * Builtin Types
 * -------------
 *
 * Boolean
 * ^^^^^^^
 * A two-state logical value (true or false). */
typedef bool UA_Boolean;
#define UA_TRUE true
#define UA_FALSE false

/**
 * SByte
 * ^^^^^
 * An integer value between -128 and 127. */
typedef int8_t UA_SByte;
#define UA_SBYTE_MIN (-128)
#define UA_SBYTE_MAX 127

/**
 * Byte
 * ^^^^
 * An integer value between 0 and 255. */
typedef uint8_t UA_Byte;
#define UA_BYTE_MIN 0
#define UA_BYTE_MAX 255

/**
 * Int16
 * ^^^^^
 * An integer value between -32 768 and 32 767. */
typedef int16_t UA_Int16;
#define UA_INT16_MIN (-32768)
#define UA_INT16_MAX 32767

/**
 * UInt16
 * ^^^^^^
 * An integer value between 0 and 65 535. */
typedef uint16_t UA_UInt16;
#define UA_UINT16_MIN 0
#define UA_UINT16_MAX 65535

/**
 * Int32
 * ^^^^^
 * An integer value between -2 147 483 648 and 2 147 483 647. */
typedef int32_t UA_Int32;
#define UA_INT32_MIN (-2147483648)
#define UA_INT32_MAX 2147483647

/**
 * UInt32
 * ^^^^^^
 * An integer value between 0 and 4 294 967 295. */
typedef uint32_t UA_UInt32;
#define UA_UINT32_MIN 0
#define UA_UINT32_MAX 4294967295

/**
 * Int64
 * ^^^^^
 * An integer value between -9 223 372 036 854 775 808 and
 * 9 223 372 036 854 775 807. */
typedef int64_t UA_Int64;
#define UA_INT64_MIN ((int64_t)-9223372036854775808)
#define UA_INT64_MAX (int64_t)9223372036854775807

/**
 * UInt64
 * ^^^^^^
 * An integer value between 0 and 18 446 744 073 709 551 615. */
typedef uint64_t UA_UInt64;
#define UA_UINT64_MIN (int64_t)0
#define UA_UINT64_MAX (int64_t)18446744073709551615

/**
 * Float
 * ^^^^^
 * An IEEE single precision (32 bit) floating point value. */
typedef float UA_Float;

/**
 * Double
 * ^^^^^^
 * An IEEE double precision (64 bit) floating point value. */
typedef double UA_Double;

/**
 * .. _statuscode:
 *
 * StatusCode
 * ^^^^^^^^^^
 * A numeric identifier for a error or condition that is associated with a value
 * or an operation. See the section :ref:`statuscodes` for the meaning of a
 * specific code. */
typedef uint32_t UA_StatusCode;

/* Returns the human-readable name of the StatusCode. If no matching StatusCode
 * is found, a default string for "Unknown" is returned. This feature might be
 * disabled to create a smaller binary with the
 * UA_ENABLE_STATUSCODE_DESCRIPTIONS build-flag. Then the function returns an
 * empty string for every StatusCode. */
UA_EXPORT const char *
UA_StatusCode_name(UA_StatusCode code);

/**
 * String
 * ^^^^^^
 * A sequence of Unicode characters. Strings are just an array of UA_Byte. */
typedef struct {
    size_t length; /* The length of the string */
    UA_Byte *data; /* The content (not null-terminated) */
} UA_String;

/* Copies the content on the heap. Returns a null-string when alloc fails */
UA_String UA_EXPORT UA_String_fromChars(char const src[]) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

UA_Boolean UA_EXPORT UA_String_equal(const UA_String *s1, const UA_String *s2);

UA_EXPORT extern const UA_String UA_STRING_NULL;

/**
 * ``UA_STRING`` returns a string pointing to the original char-array.
 * ``UA_STRING_ALLOC`` is shorthand for ``UA_String_fromChars`` and makes a copy
 * of the char-array. */
static UA_INLINE UA_String
UA_STRING(char *chars) {
    UA_String str; str.length = strlen(chars);
    str.data = (UA_Byte*)chars; return str;
}

#define UA_STRING_ALLOC(CHARS) UA_String_fromChars(CHARS)

/* Define strings at compile time (in ROM) */
#define UA_STRING_STATIC(CHARS) {sizeof(CHARS)-1, (UA_Byte*)CHARS}

/**
 * .. _datetime:
 *
 * DateTime
 * ^^^^^^^^
 * An instance in time. A DateTime value is encoded as a 64-bit signed integer
 * which represents the number of 100 nanosecond intervals since January 1, 1601
 * (UTC).
 *
 * The methods providing an interface to the system clock are provided by a
 * "plugin" that is statically linked with the library. */

typedef int64_t UA_DateTime;

/* Multiples to convert durations to DateTime */
#define UA_DATETIME_USEC 10LL
#define UA_DATETIME_MSEC (UA_DATETIME_USEC * 1000LL)
#define UA_DATETIME_SEC (UA_DATETIME_MSEC * 1000LL)

/* The current time in UTC time */
UA_DateTime UA_EXPORT UA_DateTime_now(void);

/* Offset between local time and UTC time */
UA_Int64 UA_EXPORT UA_DateTime_localTimeUtcOffset(void);

/* CPU clock invariant to system time changes. Use only to measure durations,
 * not absolute time. */
UA_DateTime UA_EXPORT UA_DateTime_nowMonotonic(void);

/* Represents a Datetime as a structure */
typedef struct UA_DateTimeStruct {
    UA_UInt16 nanoSec;
    UA_UInt16 microSec;
    UA_UInt16 milliSec;
    UA_UInt16 sec;
    UA_UInt16 min;
    UA_UInt16 hour;
    UA_UInt16 day;
    UA_UInt16 month;
    UA_UInt16 year;
} UA_DateTimeStruct;

UA_DateTimeStruct UA_EXPORT UA_DateTime_toStruct(UA_DateTime t);

/* The C99 standard (7.23.1) says: "The range and precision of times
 * representable in clock_t and time_t are implementation-defined." On most
 * systems, time_t is a 4 or 8 byte integer counting seconds since the UTC Unix
 * epoch. The following methods are used for conversion. */

/* Datetime of 1 Jan 1970 00:00 */
#define UA_DATETIME_UNIX_EPOCH (11644473600LL * UA_DATETIME_SEC)

static UA_INLINE UA_Int64
UA_DateTime_toUnixTime(UA_DateTime date) {
    return (date - UA_DATETIME_UNIX_EPOCH) / UA_DATETIME_SEC;
}

static UA_INLINE UA_DateTime
UA_DateTime_fromUnixTime(UA_Int64 unixDate) {
    return (unixDate * UA_DATETIME_SEC) + UA_DATETIME_UNIX_EPOCH;
}

/**
 * Guid
 * ^^^^
 * A 16 byte value that can be used as a globally unique identifier. */
typedef struct {
    UA_UInt32 data1;
    UA_UInt16 data2;
    UA_UInt16 data3;
    UA_Byte   data4[8];
} UA_Guid;

UA_Boolean UA_EXPORT UA_Guid_equal(const UA_Guid *g1, const UA_Guid *g2);

UA_EXPORT extern const UA_Guid UA_GUID_NULL;

/**
 * ByteString
 * ^^^^^^^^^^
 * A sequence of octets. */
typedef UA_String UA_ByteString;

static UA_INLINE UA_Boolean
UA_ByteString_equal(const UA_ByteString *string1,
                    const UA_ByteString *string2) {
    return UA_String_equal((const UA_String*)string1,
                           (const UA_String*)string2);
}

/* Allocates memory of size length for the bytestring.
 * The content is not set to zero. */
UA_StatusCode UA_EXPORT
UA_ByteString_allocBuffer(UA_ByteString *bs, size_t length);

UA_EXPORT extern const UA_ByteString UA_BYTESTRING_NULL;

static UA_INLINE UA_ByteString
UA_BYTESTRING(char *chars) {
    UA_ByteString str; str.length = strlen(chars);
    str.data = (UA_Byte*)chars; return str;
}

static UA_INLINE UA_ByteString
UA_BYTESTRING_ALLOC(const char *chars) {
    UA_String str = UA_String_fromChars(chars); UA_ByteString bstr;
    bstr.length = str.length; bstr.data = str.data; return bstr;
}

/**
 * XmlElement
 * ^^^^^^^^^^
 * An XML element. */
typedef UA_String UA_XmlElement;

/**
 * .. _nodeid:
 *
 * NodeId
 * ^^^^^^
 * An identifier for a node in the address space of an OPC UA Server. */
enum UA_NodeIdType {
    UA_NODEIDTYPE_NUMERIC    = 0, /* In the binary encoding, this can also
                                     become 1 or 2 (2byte and 4byte encoding of
                                     small numeric nodeids) */
    UA_NODEIDTYPE_STRING     = 3,
    UA_NODEIDTYPE_GUID       = 4,
    UA_NODEIDTYPE_BYTESTRING = 5
};

typedef struct {
    UA_UInt16 namespaceIndex;
    enum UA_NodeIdType identifierType;
    union {
        UA_UInt32     numeric;
        UA_String     string;
        UA_Guid       guid;
        UA_ByteString byteString;
    } identifier;
} UA_NodeId;

UA_EXPORT extern const UA_NodeId UA_NODEID_NULL;

UA_Boolean UA_EXPORT UA_NodeId_isNull(const UA_NodeId *p);

UA_Boolean UA_EXPORT UA_NodeId_equal(const UA_NodeId *n1, const UA_NodeId *n2);

/* Returns a non-cryptographic hash for the NodeId */
UA_UInt32 UA_EXPORT UA_NodeId_hash(const UA_NodeId *n);

/** The following functions are shorthand for creating NodeIds. */
static UA_INLINE UA_NodeId
UA_NODEID_NUMERIC(UA_UInt16 nsIndex, UA_UInt32 identifier) {
    UA_NodeId id; id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_NUMERIC;
    id.identifier.numeric = identifier; return id;
}

static UA_INLINE UA_NodeId
UA_NODEID_STRING(UA_UInt16 nsIndex, char *chars) {
    UA_NodeId id; id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_STRING;
    id.identifier.string = UA_STRING(chars); return id;
}

static UA_INLINE UA_NodeId
UA_NODEID_STRING_ALLOC(UA_UInt16 nsIndex, const char *chars) {
    UA_NodeId id; id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_STRING;
    id.identifier.string = UA_STRING_ALLOC(chars); return id;
}

static UA_INLINE UA_NodeId
UA_NODEID_GUID(UA_UInt16 nsIndex, UA_Guid guid) {
    UA_NodeId id; id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_GUID;
    id.identifier.guid = guid; return id;
}

static UA_INLINE UA_NodeId
UA_NODEID_BYTESTRING(UA_UInt16 nsIndex, char *chars) {
    UA_NodeId id; id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_BYTESTRING;
    id.identifier.byteString = UA_BYTESTRING(chars); return id;
}

static UA_INLINE UA_NodeId
UA_NODEID_BYTESTRING_ALLOC(UA_UInt16 nsIndex, const char *chars) {
    UA_NodeId id; id.namespaceIndex = nsIndex;
    id.identifierType = UA_NODEIDTYPE_BYTESTRING;
    id.identifier.byteString = UA_BYTESTRING_ALLOC(chars); return id;
}

/**
 * ExpandedNodeId
 * ^^^^^^^^^^^^^^
 * A NodeId that allows the namespace URI to be specified instead of an index. */
typedef struct {
    UA_NodeId nodeId;
    UA_String namespaceUri;
    UA_UInt32 serverIndex;
} UA_ExpandedNodeId;

UA_Boolean UA_EXPORT UA_ExpandedNodeId_equal(const UA_ExpandedNodeId *n1,
                                             const UA_ExpandedNodeId *n2);

UA_EXPORT extern const UA_ExpandedNodeId UA_EXPANDEDNODEID_NULL;

/** The following functions are shorthand for creating ExpandedNodeIds. */
static UA_INLINE UA_ExpandedNodeId
UA_EXPANDEDNODEID_NUMERIC(UA_UInt16 nsIndex, UA_UInt32 identifier) {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_NUMERIC(nsIndex, identifier);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
}

static UA_INLINE UA_ExpandedNodeId
UA_EXPANDEDNODEID_STRING(UA_UInt16 nsIndex, char *chars) {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_STRING(nsIndex, chars);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
}

static UA_INLINE UA_ExpandedNodeId
UA_EXPANDEDNODEID_STRING_ALLOC(UA_UInt16 nsIndex, const char *chars) {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_STRING_ALLOC(nsIndex, chars);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
}

static UA_INLINE UA_ExpandedNodeId
UA_EXPANDEDNODEID_STRING_GUID(UA_UInt16 nsIndex, UA_Guid guid) {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_GUID(nsIndex, guid);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
}

static UA_INLINE UA_ExpandedNodeId
UA_EXPANDEDNODEID_BYTESTRING(UA_UInt16 nsIndex, char *chars) {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_BYTESTRING(nsIndex, chars);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
}

static UA_INLINE UA_ExpandedNodeId
UA_EXPANDEDNODEID_BYTESTRING_ALLOC(UA_UInt16 nsIndex, const char *chars) {
    UA_ExpandedNodeId id; id.nodeId = UA_NODEID_BYTESTRING_ALLOC(nsIndex, chars);
    id.serverIndex = 0; id.namespaceUri = UA_STRING_NULL; return id;
}

/**
 * .. _qualifiedname:
 *
 * QualifiedName
 * ^^^^^^^^^^^^^
 * A name qualified by a namespace. */
typedef struct {
    UA_UInt16 namespaceIndex;
    UA_String name;
} UA_QualifiedName;

static UA_INLINE UA_Boolean
UA_QualifiedName_isNull(const UA_QualifiedName *q) {
    return (q->namespaceIndex == 0 && q->name.length == 0);
}

static UA_INLINE UA_QualifiedName
UA_QUALIFIEDNAME(UA_UInt16 nsIndex, char *chars) {
    UA_QualifiedName qn; qn.namespaceIndex = nsIndex;
    qn.name = UA_STRING(chars); return qn;
}

static UA_INLINE UA_QualifiedName
UA_QUALIFIEDNAME_ALLOC(UA_UInt16 nsIndex, const char *chars) {
    UA_QualifiedName qn; qn.namespaceIndex = nsIndex;
    qn.name = UA_STRING_ALLOC(chars); return qn;
}

UA_Boolean UA_EXPORT
UA_QualifiedName_equal(const UA_QualifiedName *qn1,
                       const UA_QualifiedName *qn2);

/**
 * LocalizedText
 * ^^^^^^^^^^^^^
 * Human readable text with an optional locale identifier. */
typedef struct {
    UA_String locale;
    UA_String text;
} UA_LocalizedText;

static UA_INLINE UA_LocalizedText
UA_LOCALIZEDTEXT(char *locale, char *text) {
    UA_LocalizedText lt; lt.locale = UA_STRING(locale);
    lt.text = UA_STRING(text); return lt;
}

static UA_INLINE UA_LocalizedText
UA_LOCALIZEDTEXT_ALLOC(const char *locale, const char *text) {
    UA_LocalizedText lt; lt.locale = UA_STRING_ALLOC(locale);
    lt.text = UA_STRING_ALLOC(text); return lt;
}

/**
 * .. _numericrange:
 *
 * NumericRange
 * ^^^^^^^^^^^^
 *
 * NumericRanges are used to indicate subsets of a (multidimensional) array.
 * They no official data type in the OPC UA standard and are transmitted only
 * with a string encoding, such as "1:2,0:3,5". The colon separates min/max
 * index and the comma separates dimensions. A single value indicates a range
 * with a single element (min==max). */
typedef struct {
    UA_UInt32 min;
    UA_UInt32 max;
} UA_NumericRangeDimension;

typedef struct  {
    size_t dimensionsSize;
    UA_NumericRangeDimension *dimensions;
} UA_NumericRange;

/**
 * .. _variant:
 *
 * Variant
 * ^^^^^^^
 *
 * Variants may contain values of any type together with a description of the
 * content. See the section on :ref:`generic-types` on how types are described.
 * The standard mandates that variants contain built-in data types only. If the
 * value is not of a builtin type, it is wrapped into an :ref:`extensionobject`.
 * open62541 hides this wrapping transparently in the encoding layer. If the
 * data type is unknown to the receiver, the variant contains the original
 * ExtensionObject in binary or XML encoding.
 *
 * Variants may contain a scalar value or an array. For details on the handling
 * of arrays, see the section on :ref:`array-handling`. Array variants can have
 * an additional dimensionality (matrix, 3-tensor, ...) defined in an array of
 * dimension lengths. The actual values are kept in an array of dimensions one.
 * For users who work with higher-dimensions arrays directly, keep in mind that
 * dimensions of higher rank are serialized first (the highest rank dimension
 * has stride 1 and elements follow each other directly). Usually it is simplest
 * to interact with higher-dimensional arrays via ``UA_NumericRange``
 * descriptions (see :ref:`array-handling`).
 *
 * To differentiate between scalar / array variants, the following definition is
 * used. ``UA_Variant_isScalar`` provides simplified access to these checks.
 *
 * - ``arrayLength == 0 && data == NULL``: undefined array of length -1
 * - ``arrayLength == 0 && data == UA_EMPTY_ARRAY_SENTINEL``: array of length 0
 * - ``arrayLength == 0 && data > UA_EMPTY_ARRAY_SENTINEL``: scalar value
 * - ``arrayLength > 0``: array of the given length
 *
 * Variants can also be *empty*. Then, the pointer to the type description is
 * ``NULL``. */
/* Forward declaration. See the section on Generic Type Handling */
struct UA_DataType;
typedef struct UA_DataType UA_DataType;

#define UA_EMPTY_ARRAY_SENTINEL ((void*)0x01)

typedef enum {
    UA_VARIANT_DATA,          /* The data has the same lifecycle as the
                                 variant */
    UA_VARIANT_DATA_NODELETE /* The data is "borrowed" by the variant and
                                 shall not be deleted at the end of the
                                 variant's lifecycle. */
} UA_VariantStorageType;

typedef struct {
    const UA_DataType *type;      /* The data type description */
    UA_VariantStorageType storageType;
    size_t arrayLength;           /* The number of elements in the data array */
    void *data;                   /* Points to the scalar or array data */
    size_t arrayDimensionsSize;   /* The number of dimensions */
    UA_UInt32 *arrayDimensions;   /* The length of each dimension */
} UA_Variant;

/* Returns true if the variant has no value defined (contains neither an array
 * nor a scalar value).
 *
 * @param v The variant
 * @return Is the variant empty */
static UA_INLINE UA_Boolean
UA_Variant_isEmpty(const UA_Variant *v) {
    return v->type == NULL;
}

/* Returns true if the variant contains a scalar value. Note that empty variants
 * contain an array of length -1 (undefined).
 *
 * @param v The variant
 * @return Does the variant contain a scalar value */
static UA_INLINE UA_Boolean
UA_Variant_isScalar(const UA_Variant *v) {
    return (v->arrayLength == 0 && v->data > UA_EMPTY_ARRAY_SENTINEL);
}

/* Returns true if the variant contains a scalar value of the given type.
 *
 * @param v The variant
 * @param type The data type
 * @return Does the variant contain a scalar value of the given type */
static UA_INLINE UA_Boolean
UA_Variant_hasScalarType(const UA_Variant *v, const UA_DataType *type) {
    return UA_Variant_isScalar(v) && type == v->type;
}

/* Returns true if the variant contains an array of the given type.
 *
 * @param v The variant
 * @param type The data type
 * @return Does the variant contain an array of the given type */
static UA_INLINE UA_Boolean
UA_Variant_hasArrayType(const UA_Variant *v, const UA_DataType *type) {
    return (!UA_Variant_isScalar(v)) && type == v->type;
}

/* Set the variant to a scalar value that already resides in memory. The value
 * takes on the lifecycle of the variant and is deleted with it.
 *
 * @param v The variant
 * @param p A pointer to the value data
 * @param type The datatype of the value in question */
void UA_EXPORT
UA_Variant_setScalar(UA_Variant *v, void * UA_RESTRICT p,
                     const UA_DataType *type);

/* Set the variant to a scalar value that is copied from an existing variable.
 * @param v The variant
 * @param p A pointer to the value data
 * @param type The datatype of the value
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_Variant_setScalarCopy(UA_Variant *v, const void *p,
                         const UA_DataType *type);

/* Set the variant to an array that already resides in memory. The array takes
 * on the lifecycle of the variant and is deleted with it.
 *
 * @param v The variant
 * @param array A pointer to the array data
 * @param arraySize The size of the array
 * @param type The datatype of the array */
void UA_EXPORT
UA_Variant_setArray(UA_Variant *v, void * UA_RESTRICT array,
                    size_t arraySize, const UA_DataType *type);

/* Set the variant to an array that is copied from an existing array.
 *
 * @param v The variant
 * @param array A pointer to the array data
 * @param arraySize The size of the array
 * @param type The datatype of the array
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_Variant_setArrayCopy(UA_Variant *v, const void *array,
                        size_t arraySize, const UA_DataType *type);

/* Copy the variant, but use only a subset of the (multidimensional) array into
 * a variant. Returns an error code if the variant is not an array or if the
 * indicated range does not fit.
 *
 * @param src The source variant
 * @param dst The target variant
 * @param range The range of the copied data
 * @return Returns UA_STATUSCODE_GOOD or an error code */
UA_StatusCode UA_EXPORT
UA_Variant_copyRange(const UA_Variant *src, UA_Variant *dst,
                     const UA_NumericRange range);

/* Insert a range of data into an existing variant. The data array can't be
 * reused afterwards if it contains types without a fixed size (e.g. strings)
 * since the members are moved into the variant and take on its lifecycle.
 *
 * @param v The variant
 * @param dataArray The data array. The type must match the variant
 * @param dataArraySize The length of the data array. This is checked to match
 *        the range size.
 * @param range The range of where the new data is inserted
 * @return Returns UA_STATUSCODE_GOOD or an error code */
UA_StatusCode UA_EXPORT
UA_Variant_setRange(UA_Variant *v, void * UA_RESTRICT array,
                    size_t arraySize, const UA_NumericRange range);

/* Deep-copy a range of data into an existing variant.
 *
 * @param v The variant
 * @param dataArray The data array. The type must match the variant
 * @param dataArraySize The length of the data array. This is checked to match
 *        the range size.
 * @param range The range of where the new data is inserted
 * @return Returns UA_STATUSCODE_GOOD or an error code */
UA_StatusCode UA_EXPORT
UA_Variant_setRangeCopy(UA_Variant *v, const void *array,
                        size_t arraySize, const UA_NumericRange range);

/**
 * .. _extensionobject:
 *
 * ExtensionObject
 * ^^^^^^^^^^^^^^^
 *
 * ExtensionObjects may contain scalars of any data type. Even those that are
 * unknown to the receiver. See the section on :ref:`generic-types` on how types
 * are described. If the received data type is unknown, the encoded string and
 * target NodeId is stored instead of the decoded value. */
typedef enum {
    UA_EXTENSIONOBJECT_ENCODED_NOBODY     = 0,
    UA_EXTENSIONOBJECT_ENCODED_BYTESTRING = 1,
    UA_EXTENSIONOBJECT_ENCODED_XML        = 2,
    UA_EXTENSIONOBJECT_DECODED            = 3,
    UA_EXTENSIONOBJECT_DECODED_NODELETE   = 4 /* Don't delete the content
                                                 together with the
                                                 ExtensionObject */
} UA_ExtensionObjectEncoding;

typedef struct {
    UA_ExtensionObjectEncoding encoding;
    union {
        struct {
            UA_NodeId typeId;   /* The nodeid of the datatype */
            UA_ByteString body; /* The bytestring of the encoded data */
        } encoded;
        struct {
            const UA_DataType *type;
            void *data;
        } decoded;
    } content;
} UA_ExtensionObject;

/**
 * .. _datavalue:
 *
 * DataValue
 * ^^^^^^^^^
 * A data value with an associated status code and timestamps. */
typedef struct {
    UA_Boolean    hasValue             : 1;
    UA_Boolean    hasStatus            : 1;
    UA_Boolean    hasSourceTimestamp   : 1;
    UA_Boolean    hasServerTimestamp   : 1;
    UA_Boolean    hasSourcePicoseconds : 1;
    UA_Boolean    hasServerPicoseconds : 1;
    UA_Variant    value;
    UA_StatusCode status;
    UA_DateTime   sourceTimestamp;
    UA_UInt16     sourcePicoseconds;
    UA_DateTime   serverTimestamp;
    UA_UInt16     serverPicoseconds;
} UA_DataValue;

/**
 * DiagnosticInfo
 * ^^^^^^^^^^^^^^
 * A structure that contains detailed error and diagnostic information
 * associated with a StatusCode. */
typedef struct UA_DiagnosticInfo {
    UA_Boolean    hasSymbolicId          : 1;
    UA_Boolean    hasNamespaceUri        : 1;
    UA_Boolean    hasLocalizedText       : 1;
    UA_Boolean    hasLocale              : 1;
    UA_Boolean    hasAdditionalInfo      : 1;
    UA_Boolean    hasInnerStatusCode     : 1;
    UA_Boolean    hasInnerDiagnosticInfo : 1;
    UA_Int32      symbolicId;
    UA_Int32      namespaceUri;
    UA_Int32      localizedText;
    UA_Int32      locale;
    UA_String     additionalInfo;
    UA_StatusCode innerStatusCode;
    struct UA_DiagnosticInfo *innerDiagnosticInfo;
} UA_DiagnosticInfo;

/**
 * .. _generic-types:
 *
 * Generic Type Handling
 * ---------------------
 *
 * All information about a (builtin/structured) data type is stored in a
 * ``UA_DataType``. The array ``UA_TYPES`` contains the description of all
 * standard-defined types. This type description is used for the following
 * generic operations that work on all types:
 *
 * - ``void T_init(T *ptr)``: Initialize the data type. This is synonymous with
 *   zeroing out the memory, i.e. ``memset(ptr, 0, sizeof(T))``.
 * - ``T* T_new()``: Allocate and return the memory for the data type. The
 *   value is already initialized.
 * - ``UA_StatusCode T_copy(const T *src, T *dst)``: Copy the content of the
 *   data type. Returns ``UA_STATUSCODE_GOOD`` or
 *   ``UA_STATUSCODE_BADOUTOFMEMORY``.
 * - ``void T_deleteMembers(T *ptr)``: Delete the dynamically allocated content
 *   of the data type and perform a ``T_init`` to reset the type.
 * - ``void T_delete(T *ptr)``: Delete the content of the data type and the
 *   memory for the data type itself.
 *
 * Specializations, such as ``UA_Int32_new()`` are derived from the generic
 * type operations as static inline functions. */

typedef struct {
#ifdef UA_ENABLE_TYPENAMES
    const char *memberName;
#endif
    UA_UInt16 memberTypeIndex;    /* Index of the member in the array of data
                                     types */
    UA_Byte   padding;            /* How much padding is there before this
                                     member element? For arrays this is the
                                     padding before the size_t length member.
                                     (No padding between size_t and the
                                     following ptr.) */
    UA_Boolean namespaceZero : 1; /* The type of the member is defined in
                                     namespace zero. In this implementation,
                                     types from custom namespace may contain
                                     members from the same namespace or
                                     namespace zero only.*/
    UA_Boolean isArray       : 1; /* The member is an array */
} UA_DataTypeMember;

struct UA_DataType {
#ifdef UA_ENABLE_TYPENAMES
    const char *typeName;
#endif
    UA_NodeId  typeId;           /* The nodeid of the type */
    UA_UInt16  memSize;          /* Size of the struct in memory */
    UA_UInt16  typeIndex;        /* Index of the type in the datatypetable */
    UA_Byte    membersSize;      /* How many members does the type have? */
    UA_Boolean builtin      : 1; /* The type is "builtin" and has dedicated de-
                                    and encoding functions */
    UA_Boolean pointerFree  : 1; /* The type (and its members) contains no
                                    pointers that need to be freed */
    UA_Boolean overlayable  : 1; /* The type has the identical memory layout in
                                    memory and on the binary stream. */
    UA_UInt16  binaryEncodingId; /* NodeId of datatype when encoded as binary */
    //UA_UInt16  xmlEncodingId;  /* NodeId of datatype when encoded as XML */
    UA_DataTypeMember *members;
};

/* Test if the data type is a numeric builtin data type. This includes Boolean,
 * integers and floating point numbers. Not included are DateTime and
 * StatusCode. */
UA_Boolean
isDataTypeNumeric(const UA_DataType *type);

/* The following is used to exclude type names in the definition of UA_DataType
 * structures if the feature is disabled. */
#ifdef UA_ENABLE_TYPENAMES
# define UA_TYPENAME(name) name,
#else
# define UA_TYPENAME(name)
#endif

/**
 * Builtin data types can be accessed as UA_TYPES[UA_TYPES_XXX], where XXX is
 * the name of the data type. If only the NodeId of a type is known, use the
 * following method to retrieve the data type description. */

/* Returns the data type description for the type's identifier or NULL if no
 * matching data type was found. */
const UA_DataType UA_EXPORT *
UA_findDataType(const UA_NodeId *typeId);

/** The following functions are used for generic handling of data types. */

/* Allocates and initializes a variable of type dataType
 *
 * @param type The datatype description
 * @return Returns the memory location of the variable or NULL if no
 *         memory could be allocated */
void UA_EXPORT * UA_new(const UA_DataType *type) UA_FUNC_ATTR_MALLOC;

/* Initializes a variable to default values
 *
 * @param p The memory location of the variable
 * @param type The datatype description */
static UA_INLINE void
UA_init(void *p, const UA_DataType *type) {
    memset(p, 0, type->memSize);
}

/* Copies the content of two variables. If copying fails (e.g. because no memory
 * was available for an array), then dst is emptied and initialized to prevent
 * memory leaks.
 *
 * @param src The memory location of the source variable
 * @param dst The memory location of the destination variable
 * @param type The datatype description
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_copy(const void *src, void *dst, const UA_DataType *type);

/* Deletes the dynamically allocated content of a variable (e.g. resets all
 * arrays to undefined arrays). Afterwards, the variable can be safely deleted
 * without causing memory leaks. But the variable is not initialized and may
 * contain old data that is not memory-relevant.
 *
 * @param p The memory location of the variable
 * @param type The datatype description of the variable */
void UA_EXPORT UA_deleteMembers(void *p, const UA_DataType *type);

/* Frees a variable and all of its content.
 *
 * @param p The memory location of the variable
 * @param type The datatype description of the variable */
void UA_EXPORT UA_delete(void *p, const UA_DataType *type);

/**
 * .. _array-handling:
 *
 * Array handling
 * --------------
 * In OPC UA, arrays can have a length of zero or more with the usual meaning.
 * In addition, arrays can be undefined. Then, they don't even have a length. In
 * the binary encoding, this is indicated by an array of length -1.
 *
 * In open62541 however, we use ``size_t`` for array lengths. An undefined array
 * has length 0 and the data pointer is ``NULL``. An array of length 0 also has
 * length 0 but a data pointer ``UA_EMPTY_ARRAY_SENTINEL``. */
/* Allocates and initializes an array of variables of a specific type
 *
 * @param size The requested array length
 * @param type The datatype description
 * @return Returns the memory location of the variable or NULL if no memory
           could be allocated */
void UA_EXPORT * UA_Array_new(size_t size, const UA_DataType *type) UA_FUNC_ATTR_MALLOC;

/* Allocates and copies an array
 *
 * @param src The memory location of the source array
 * @param size The size of the array
 * @param dst The location of the pointer to the new array
 * @param type The datatype of the array members
 * @return Returns UA_STATUSCODE_GOOD or UA_STATUSCODE_BADOUTOFMEMORY */
UA_StatusCode UA_EXPORT
UA_Array_copy(const void *src, size_t size, void **dst,
              const UA_DataType *type) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

/* Deletes an array.
 *
 * @param p The memory location of the array
 * @param size The size of the array
 * @param type The datatype of the array members */
void UA_EXPORT UA_Array_delete(void *p, size_t size, const UA_DataType *type);

/**
 * Random Number Generator
 * -----------------------
 * If UA_ENABLE_MULTITHREADING is defined, then the seed is stored in thread
 * local storage. The seed is initialized for every thread in the
 * server/client. */
void UA_EXPORT UA_random_seed(UA_UInt64 seed);
UA_UInt32 UA_EXPORT UA_UInt32_random(void); /* no cryptographic entropy */
UA_Guid UA_EXPORT UA_Guid_random(void);     /* no cryptographic entropy */

/**
 * .. _generated-types:
 *
 * Generated Data Type Definitions
 * -------------------------------
 *
 * The following data types were auto-generated from a definition in XML format.
 *
 * .. toctree::
 *
 *    types_generated */

/**
 * Deprecated Data Types API
 * -------------------------
 * The following definitions are deprecated and will be removed in future
 * releases of open62541. */

typedef struct {
    UA_StatusCode code;      /* The numeric value of the StatusCode */
    const char* name;        /* The symbolic name */
    const char* explanation; /* Short message explaining the StatusCode */
} UA_StatusCodeDescription;

UA_EXPORT extern const UA_StatusCodeDescription statusCodeExplanation_default;

UA_DEPRECATED static UA_INLINE const UA_StatusCodeDescription *
UA_StatusCode_description(UA_StatusCode code) {
    return &statusCodeExplanation_default;
}

UA_DEPRECATED static UA_INLINE const char *
UA_StatusCode_explanation(UA_StatusCode code) {
    return statusCodeExplanation_default.name;
}

UA_DEPRECATED UA_String
UA_DateTime_toString(UA_DateTime t);

/* The old DateTime conversion macros */
UA_DEPRECATED static UA_INLINE double
deprecatedDateTimeMultiple(double multiple) {
    return multiple;
}

#define UA_USEC_TO_DATETIME deprecatedDateTimeMultiple((UA_Double)UA_DATETIME_USEC)
#define UA_MSEC_TO_DATETIME deprecatedDateTimeMultiple((UA_Double)UA_DATETIME_MSEC)
#define UA_SEC_TO_DATETIME deprecatedDateTimeMultiple((UA_Double)UA_DATETIME_SEC)
#define UA_DATETIME_TO_USEC deprecatedDateTimeMultiple(1.0 / ((UA_Double)UA_DATETIME_USEC))
#define UA_DATETIME_TO_MSEC deprecatedDateTimeMultiple(1.0 / ((UA_Double)UA_DATETIME_MSEC))
#define UA_DATETIME_TO_SEC deprecatedDateTimeMultiple(1.0 / ((UA_Double)UA_DATETIME_SEC))

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/build/src_generated/ua_types_generated.h" ***********************************/

/* Generated from Opc.Ua.Types.bsd with script /home/travis/build/open62541/open62541/tools/generate_datatypes.py
 * on host travis-job-193db498-e14a-4886-911f-7172c9e50b7a by user travis at 2018-12-19 02:27:56 */


#ifdef __cplusplus
extern "C" {
#endif

#ifdef UA_NO_AMALGAMATION

#else
#endif


/**
 * Every type is assigned an index in an array containing the type descriptions.
 * These descriptions are used during type handling (copying, deletion,
 * binary encoding, ...). */
#define UA_TYPES_COUNT 199
extern UA_EXPORT const UA_DataType UA_TYPES[UA_TYPES_COUNT];

/**
 * Boolean
 * ^^^^^^^
 */
#define UA_TYPES_BOOLEAN 0

/**
 * SByte
 * ^^^^^
 */
#define UA_TYPES_SBYTE 1

/**
 * Byte
 * ^^^^
 */
#define UA_TYPES_BYTE 2

/**
 * Int16
 * ^^^^^
 */
#define UA_TYPES_INT16 3

/**
 * UInt16
 * ^^^^^^
 */
#define UA_TYPES_UINT16 4

/**
 * Int32
 * ^^^^^
 */
#define UA_TYPES_INT32 5

/**
 * UInt32
 * ^^^^^^
 */
#define UA_TYPES_UINT32 6

/**
 * Int64
 * ^^^^^
 */
#define UA_TYPES_INT64 7

/**
 * UInt64
 * ^^^^^^
 */
#define UA_TYPES_UINT64 8

/**
 * Float
 * ^^^^^
 */
#define UA_TYPES_FLOAT 9

/**
 * Double
 * ^^^^^^
 */
#define UA_TYPES_DOUBLE 10

/**
 * String
 * ^^^^^^
 */
#define UA_TYPES_STRING 11

/**
 * DateTime
 * ^^^^^^^^
 */
#define UA_TYPES_DATETIME 12

/**
 * Guid
 * ^^^^
 */
#define UA_TYPES_GUID 13

/**
 * ByteString
 * ^^^^^^^^^^
 */
#define UA_TYPES_BYTESTRING 14

/**
 * XmlElement
 * ^^^^^^^^^^
 */
#define UA_TYPES_XMLELEMENT 15

/**
 * NodeId
 * ^^^^^^
 */
#define UA_TYPES_NODEID 16

/**
 * ExpandedNodeId
 * ^^^^^^^^^^^^^^
 */
#define UA_TYPES_EXPANDEDNODEID 17

/**
 * StatusCode
 * ^^^^^^^^^^
 */
#define UA_TYPES_STATUSCODE 18

/**
 * QualifiedName
 * ^^^^^^^^^^^^^
 */
#define UA_TYPES_QUALIFIEDNAME 19

/**
 * LocalizedText
 * ^^^^^^^^^^^^^
 */
#define UA_TYPES_LOCALIZEDTEXT 20

/**
 * ExtensionObject
 * ^^^^^^^^^^^^^^^
 */
#define UA_TYPES_EXTENSIONOBJECT 21

/**
 * DataValue
 * ^^^^^^^^^
 */
#define UA_TYPES_DATAVALUE 22

/**
 * Variant
 * ^^^^^^^
 */
#define UA_TYPES_VARIANT 23

/**
 * DiagnosticInfo
 * ^^^^^^^^^^^^^^
 */
#define UA_TYPES_DIAGNOSTICINFO 24

/**
 * SignedSoftwareCertificate
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 * A software certificate with a digital signature. */
typedef struct {
    UA_ByteString certificateData;
    UA_ByteString signature;
} UA_SignedSoftwareCertificate;

#define UA_TYPES_SIGNEDSOFTWARECERTIFICATE 25

/**
 * SemanticChangeStructureDataType
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId affected;
    UA_NodeId affectedType;
} UA_SemanticChangeStructureDataType;

#define UA_TYPES_SEMANTICCHANGESTRUCTUREDATATYPE 26

/**
 * StatusChangeNotification
 * ^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_StatusCode status;
    UA_DiagnosticInfo diagnosticInfo;
} UA_StatusChangeNotification;

#define UA_TYPES_STATUSCHANGENOTIFICATION 27

/**
 * BrowsePathTarget
 * ^^^^^^^^^^^^^^^^
 * The target of the translated path. */
typedef struct {
    UA_ExpandedNodeId targetId;
    UA_UInt32 remainingPathIndex;
} UA_BrowsePathTarget;

#define UA_TYPES_BROWSEPATHTARGET 28

/**
 * ViewAttributes
 * ^^^^^^^^^^^^^^
 * The attributes for a view node. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean containsNoLoops;
    UA_Byte eventNotifier;
} UA_ViewAttributes;

#define UA_TYPES_VIEWATTRIBUTES 29

/**
 * RequestHeader
 * ^^^^^^^^^^^^^
 * The header passed with every server request. */
typedef struct {
    UA_NodeId authenticationToken;
    UA_DateTime timestamp;
    UA_UInt32 requestHandle;
    UA_UInt32 returnDiagnostics;
    UA_String auditEntryId;
    UA_UInt32 timeoutHint;
    UA_ExtensionObject additionalHeader;
} UA_RequestHeader;

#define UA_TYPES_REQUESTHEADER 30

/**
 * MonitoredItemModifyResult
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_StatusCode statusCode;
    UA_Double revisedSamplingInterval;
    UA_UInt32 revisedQueueSize;
    UA_ExtensionObject filterResult;
} UA_MonitoredItemModifyResult;

#define UA_TYPES_MONITOREDITEMMODIFYRESULT 31

/**
 * ElementOperand
 * ^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 index;
} UA_ElementOperand;

#define UA_TYPES_ELEMENTOPERAND 32

/**
 * CloseSecureChannelRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 * Closes a secure channel. */
typedef struct {
    UA_RequestHeader requestHeader;
} UA_CloseSecureChannelRequest;

#define UA_TYPES_CLOSESECURECHANNELREQUEST 33

/**
 * AddNodesResult
 * ^^^^^^^^^^^^^^
 * A result of an add node operation. */
typedef struct {
    UA_StatusCode statusCode;
    UA_NodeId addedNodeId;
} UA_AddNodesResult;

#define UA_TYPES_ADDNODESRESULT 34

/**
 * VariableAttributes
 * ^^^^^^^^^^^^^^^^^^
 * The attributes for a variable node. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Variant value;
    UA_NodeId dataType;
    UA_Int32 valueRank;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
    UA_Byte accessLevel;
    UA_Byte userAccessLevel;
    UA_Double minimumSamplingInterval;
    UA_Boolean historizing;
} UA_VariableAttributes;

#define UA_TYPES_VARIABLEATTRIBUTES 35

/**
 * NotificationMessage
 * ^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 sequenceNumber;
    UA_DateTime publishTime;
    size_t notificationDataSize;
    UA_ExtensionObject *notificationData;
} UA_NotificationMessage;

#define UA_TYPES_NOTIFICATIONMESSAGE 36

/**
 * FindServersOnNetworkRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 startingRecordId;
    UA_UInt32 maxRecordsToReturn;
    size_t serverCapabilityFilterSize;
    UA_String *serverCapabilityFilter;
} UA_FindServersOnNetworkRequest;

#define UA_TYPES_FINDSERVERSONNETWORKREQUEST 37

/**
 * EventFieldList
 * ^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 clientHandle;
    size_t eventFieldsSize;
    UA_Variant *eventFields;
} UA_EventFieldList;

#define UA_TYPES_EVENTFIELDLIST 38

/**
 * MonitoringMode
 * ^^^^^^^^^^^^^^
 */
typedef enum {
    UA_MONITORINGMODE_DISABLED = 0,
    UA_MONITORINGMODE_SAMPLING = 1,
    UA_MONITORINGMODE_REPORTING = 2,
    __UA_MONITORINGMODE_FORCE32BIT = 0x7fffffff
} UA_MonitoringMode;
UA_STATIC_ASSERT(sizeof(UA_MonitoringMode) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_MONITORINGMODE 39

/**
 * MdnsDiscoveryConfiguration
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 * The discovery information needed for mDNS registration. */
typedef struct {
    UA_String mdnsServerName;
    size_t serverCapabilitiesSize;
    UA_String *serverCapabilities;
} UA_MdnsDiscoveryConfiguration;

#define UA_TYPES_MDNSDISCOVERYCONFIGURATION 40

/**
 * CallMethodResult
 * ^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_StatusCode statusCode;
    size_t inputArgumentResultsSize;
    UA_StatusCode *inputArgumentResults;
    size_t inputArgumentDiagnosticInfosSize;
    UA_DiagnosticInfo *inputArgumentDiagnosticInfos;
    size_t outputArgumentsSize;
    UA_Variant *outputArguments;
} UA_CallMethodResult;

#define UA_TYPES_CALLMETHODRESULT 41

/**
 * ParsingResult
 * ^^^^^^^^^^^^^
 */
typedef struct {
    UA_StatusCode statusCode;
    size_t dataStatusCodesSize;
    UA_StatusCode *dataStatusCodes;
    size_t dataDiagnosticInfosSize;
    UA_DiagnosticInfo *dataDiagnosticInfos;
} UA_ParsingResult;

#define UA_TYPES_PARSINGRESULT 42

/**
 * RelativePathElement
 * ^^^^^^^^^^^^^^^^^^^
 * An element in a relative path. */
typedef struct {
    UA_NodeId referenceTypeId;
    UA_Boolean isInverse;
    UA_Boolean includeSubtypes;
    UA_QualifiedName targetName;
} UA_RelativePathElement;

#define UA_TYPES_RELATIVEPATHELEMENT 43

/**
 * BrowseDirection
 * ^^^^^^^^^^^^^^^
 * The directions of the references to return. */
typedef enum {
    UA_BROWSEDIRECTION_FORWARD = 0,
    UA_BROWSEDIRECTION_INVERSE = 1,
    UA_BROWSEDIRECTION_BOTH = 2,
    UA_BROWSEDIRECTION_INVALID = 3,
    __UA_BROWSEDIRECTION_FORCE32BIT = 0x7fffffff
} UA_BrowseDirection;
UA_STATIC_ASSERT(sizeof(UA_BrowseDirection) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_BROWSEDIRECTION 44

/**
 * CallMethodRequest
 * ^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId objectId;
    UA_NodeId methodId;
    size_t inputArgumentsSize;
    UA_Variant *inputArguments;
} UA_CallMethodRequest;

#define UA_TYPES_CALLMETHODREQUEST 45

/**
 * RedundancySupport
 * ^^^^^^^^^^^^^^^^^
 */
typedef enum {
    UA_REDUNDANCYSUPPORT_NONE = 0,
    UA_REDUNDANCYSUPPORT_COLD = 1,
    UA_REDUNDANCYSUPPORT_WARM = 2,
    UA_REDUNDANCYSUPPORT_HOT = 3,
    UA_REDUNDANCYSUPPORT_TRANSPARENT = 4,
    UA_REDUNDANCYSUPPORT_HOTANDMIRRORED = 5,
    __UA_REDUNDANCYSUPPORT_FORCE32BIT = 0x7fffffff
} UA_RedundancySupport;
UA_STATIC_ASSERT(sizeof(UA_RedundancySupport) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_REDUNDANCYSUPPORT 46

/**
 * EventNotificationList
 * ^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    size_t eventsSize;
    UA_EventFieldList *events;
} UA_EventNotificationList;

#define UA_TYPES_EVENTNOTIFICATIONLIST 47

/**
 * UnregisterNodesRequest
 * ^^^^^^^^^^^^^^^^^^^^^^
 * Unregisters one or more previously registered nodes. */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t nodesToUnregisterSize;
    UA_NodeId *nodesToUnregister;
} UA_UnregisterNodesRequest;

#define UA_TYPES_UNREGISTERNODESREQUEST 48

/**
 * ContentFilterElementResult
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_StatusCode statusCode;
    size_t operandStatusCodesSize;
    UA_StatusCode *operandStatusCodes;
    size_t operandDiagnosticInfosSize;
    UA_DiagnosticInfo *operandDiagnosticInfos;
} UA_ContentFilterElementResult;

#define UA_TYPES_CONTENTFILTERELEMENTRESULT 49

/**
 * SimpleAttributeOperand
 * ^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId typeDefinitionId;
    size_t browsePathSize;
    UA_QualifiedName *browsePath;
    UA_UInt32 attributeId;
    UA_String indexRange;
} UA_SimpleAttributeOperand;

#define UA_TYPES_SIMPLEATTRIBUTEOPERAND 50

/**
 * LiteralOperand
 * ^^^^^^^^^^^^^^
 */
typedef struct {
    UA_Variant value;
} UA_LiteralOperand;

#define UA_TYPES_LITERALOPERAND 51

/**
 * QueryDataSet
 * ^^^^^^^^^^^^
 */
typedef struct {
    UA_ExpandedNodeId nodeId;
    UA_ExpandedNodeId typeDefinitionNode;
    size_t valuesSize;
    UA_Variant *values;
} UA_QueryDataSet;

#define UA_TYPES_QUERYDATASET 52

/**
 * AnonymousIdentityToken
 * ^^^^^^^^^^^^^^^^^^^^^^
 * A token representing an anonymous user. */
typedef struct {
    UA_String policyId;
} UA_AnonymousIdentityToken;

#define UA_TYPES_ANONYMOUSIDENTITYTOKEN 53

/**
 * SetPublishingModeRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_Boolean publishingEnabled;
    size_t subscriptionIdsSize;
    UA_UInt32 *subscriptionIds;
} UA_SetPublishingModeRequest;

#define UA_TYPES_SETPUBLISHINGMODEREQUEST 54

/**
 * MonitoredItemCreateResult
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_StatusCode statusCode;
    UA_UInt32 monitoredItemId;
    UA_Double revisedSamplingInterval;
    UA_UInt32 revisedQueueSize;
    UA_ExtensionObject filterResult;
} UA_MonitoredItemCreateResult;

#define UA_TYPES_MONITOREDITEMCREATERESULT 55

/**
 * TimestampsToReturn
 * ^^^^^^^^^^^^^^^^^^
 */
typedef enum {
    UA_TIMESTAMPSTORETURN_SOURCE = 0,
    UA_TIMESTAMPSTORETURN_SERVER = 1,
    UA_TIMESTAMPSTORETURN_BOTH = 2,
    UA_TIMESTAMPSTORETURN_NEITHER = 3,
    UA_TIMESTAMPSTORETURN_INVALID = 4,
    __UA_TIMESTAMPSTORETURN_FORCE32BIT = 0x7fffffff
} UA_TimestampsToReturn;
UA_STATIC_ASSERT(sizeof(UA_TimestampsToReturn) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_TIMESTAMPSTORETURN 56

/**
 * CallRequest
 * ^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t methodsToCallSize;
    UA_CallMethodRequest *methodsToCall;
} UA_CallRequest;

#define UA_TYPES_CALLREQUEST 57

/**
 * MethodAttributes
 * ^^^^^^^^^^^^^^^^
 * The attributes for a method node. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean executable;
    UA_Boolean userExecutable;
} UA_MethodAttributes;

#define UA_TYPES_METHODATTRIBUTES 58

/**
 * DeleteReferencesItem
 * ^^^^^^^^^^^^^^^^^^^^
 * A request to delete a node from the server address space. */
typedef struct {
    UA_NodeId sourceNodeId;
    UA_NodeId referenceTypeId;
    UA_Boolean isForward;
    UA_ExpandedNodeId targetNodeId;
    UA_Boolean deleteBidirectional;
} UA_DeleteReferencesItem;

#define UA_TYPES_DELETEREFERENCESITEM 59

/**
 * WriteValue
 * ^^^^^^^^^^
 */
typedef struct {
    UA_NodeId nodeId;
    UA_UInt32 attributeId;
    UA_String indexRange;
    UA_DataValue value;
} UA_WriteValue;

#define UA_TYPES_WRITEVALUE 60

/**
 * NodeAttributesMask
 * ^^^^^^^^^^^^^^^^^^
 * The bits used to specify default attributes for a new node. */
typedef enum {
    UA_NODEATTRIBUTESMASK_NONE = 0,
    UA_NODEATTRIBUTESMASK_ACCESSLEVEL = 1,
    UA_NODEATTRIBUTESMASK_ARRAYDIMENSIONS = 2,
    UA_NODEATTRIBUTESMASK_BROWSENAME = 4,
    UA_NODEATTRIBUTESMASK_CONTAINSNOLOOPS = 8,
    UA_NODEATTRIBUTESMASK_DATATYPE = 16,
    UA_NODEATTRIBUTESMASK_DESCRIPTION = 32,
    UA_NODEATTRIBUTESMASK_DISPLAYNAME = 64,
    UA_NODEATTRIBUTESMASK_EVENTNOTIFIER = 128,
    UA_NODEATTRIBUTESMASK_EXECUTABLE = 256,
    UA_NODEATTRIBUTESMASK_HISTORIZING = 512,
    UA_NODEATTRIBUTESMASK_INVERSENAME = 1024,
    UA_NODEATTRIBUTESMASK_ISABSTRACT = 2048,
    UA_NODEATTRIBUTESMASK_MINIMUMSAMPLINGINTERVAL = 4096,
    UA_NODEATTRIBUTESMASK_NODECLASS = 8192,
    UA_NODEATTRIBUTESMASK_NODEID = 16384,
    UA_NODEATTRIBUTESMASK_SYMMETRIC = 32768,
    UA_NODEATTRIBUTESMASK_USERACCESSLEVEL = 65536,
    UA_NODEATTRIBUTESMASK_USEREXECUTABLE = 131072,
    UA_NODEATTRIBUTESMASK_USERWRITEMASK = 262144,
    UA_NODEATTRIBUTESMASK_VALUERANK = 524288,
    UA_NODEATTRIBUTESMASK_WRITEMASK = 1048576,
    UA_NODEATTRIBUTESMASK_VALUE = 2097152,
    UA_NODEATTRIBUTESMASK_DATATYPEDEFINITION = 4194304,
    UA_NODEATTRIBUTESMASK_ROLEPERMISSIONS = 8388608,
    UA_NODEATTRIBUTESMASK_ACCESSRESTRICTIONS = 16777216,
    UA_NODEATTRIBUTESMASK_ALL = 33554431,
    UA_NODEATTRIBUTESMASK_BASENODE = 26501220,
    UA_NODEATTRIBUTESMASK_OBJECT = 26501348,
    UA_NODEATTRIBUTESMASK_OBJECTTYPE = 26503268,
    UA_NODEATTRIBUTESMASK_VARIABLE = 26571383,
    UA_NODEATTRIBUTESMASK_VARIABLETYPE = 28600438,
    UA_NODEATTRIBUTESMASK_METHOD = 26632548,
    UA_NODEATTRIBUTESMASK_REFERENCETYPE = 26537060,
    UA_NODEATTRIBUTESMASK_VIEW = 26501356,
    __UA_NODEATTRIBUTESMASK_FORCE32BIT = 0x7fffffff
} UA_NodeAttributesMask;
UA_STATIC_ASSERT(sizeof(UA_NodeAttributesMask) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_NODEATTRIBUTESMASK 61

/**
 * MessageSecurityMode
 * ^^^^^^^^^^^^^^^^^^^
 * The type of security to use on a message. */
typedef enum {
    UA_MESSAGESECURITYMODE_INVALID = 0,
    UA_MESSAGESECURITYMODE_NONE = 1,
    UA_MESSAGESECURITYMODE_SIGN = 2,
    UA_MESSAGESECURITYMODE_SIGNANDENCRYPT = 3,
    __UA_MESSAGESECURITYMODE_FORCE32BIT = 0x7fffffff
} UA_MessageSecurityMode;
UA_STATIC_ASSERT(sizeof(UA_MessageSecurityMode) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_MESSAGESECURITYMODE 62

/**
 * MonitoringParameters
 * ^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 clientHandle;
    UA_Double samplingInterval;
    UA_ExtensionObject filter;
    UA_UInt32 queueSize;
    UA_Boolean discardOldest;
} UA_MonitoringParameters;

#define UA_TYPES_MONITORINGPARAMETERS 63

/**
 * ReferenceNode
 * ^^^^^^^^^^^^^
 * Specifies a reference which belongs to a node. */
typedef struct {
    UA_NodeId referenceTypeId;
    UA_Boolean isInverse;
    UA_ExpandedNodeId targetId;
} UA_ReferenceNode;

#define UA_TYPES_REFERENCENODE 64

/**
 * Argument
 * ^^^^^^^^
 * An argument for a method. */
typedef struct {
    UA_String name;
    UA_NodeId dataType;
    UA_Int32 valueRank;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
    UA_LocalizedText description;
} UA_Argument;

#define UA_TYPES_ARGUMENT 65

/**
 * ChannelSecurityToken
 * ^^^^^^^^^^^^^^^^^^^^
 * The token that identifies a set of keys for an active secure channel. */
typedef struct {
    UA_UInt32 channelId;
    UA_UInt32 tokenId;
    UA_DateTime createdAt;
    UA_UInt32 revisedLifetime;
} UA_ChannelSecurityToken;

#define UA_TYPES_CHANNELSECURITYTOKEN 66

/**
 * UserIdentityToken
 * ^^^^^^^^^^^^^^^^^
 * A base type for a user identity token. */
typedef struct {
    UA_String policyId;
} UA_UserIdentityToken;

#define UA_TYPES_USERIDENTITYTOKEN 67

/**
 * SignatureData
 * ^^^^^^^^^^^^^
 * A digital signature. */
typedef struct {
    UA_String algorithm;
    UA_ByteString signature;
} UA_SignatureData;

#define UA_TYPES_SIGNATUREDATA 68

/**
 * ObjectTypeAttributes
 * ^^^^^^^^^^^^^^^^^^^^
 * The attributes for an object type node. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean isAbstract;
} UA_ObjectTypeAttributes;

#define UA_TYPES_OBJECTTYPEATTRIBUTES 69

/**
 * DeadbandType
 * ^^^^^^^^^^^^
 */
typedef enum {
    UA_DEADBANDTYPE_NONE = 0,
    UA_DEADBANDTYPE_ABSOLUTE = 1,
    UA_DEADBANDTYPE_PERCENT = 2,
    __UA_DEADBANDTYPE_FORCE32BIT = 0x7fffffff
} UA_DeadbandType;
UA_STATIC_ASSERT(sizeof(UA_DeadbandType) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_DEADBANDTYPE 70

/**
 * SecurityTokenRequestType
 * ^^^^^^^^^^^^^^^^^^^^^^^^
 * Indicates whether a token if being created or renewed. */
typedef enum {
    UA_SECURITYTOKENREQUESTTYPE_ISSUE = 0,
    UA_SECURITYTOKENREQUESTTYPE_RENEW = 1,
    __UA_SECURITYTOKENREQUESTTYPE_FORCE32BIT = 0x7fffffff
} UA_SecurityTokenRequestType;
UA_STATIC_ASSERT(sizeof(UA_SecurityTokenRequestType) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_SECURITYTOKENREQUESTTYPE 71

/**
 * NodeAttributes
 * ^^^^^^^^^^^^^^
 * The base attributes for all nodes. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
} UA_NodeAttributes;

#define UA_TYPES_NODEATTRIBUTES 72

/**
 * DataChangeTrigger
 * ^^^^^^^^^^^^^^^^^
 */
typedef enum {
    UA_DATACHANGETRIGGER_STATUS = 0,
    UA_DATACHANGETRIGGER_STATUSVALUE = 1,
    UA_DATACHANGETRIGGER_STATUSVALUETIMESTAMP = 2,
    __UA_DATACHANGETRIGGER_FORCE32BIT = 0x7fffffff
} UA_DataChangeTrigger;
UA_STATIC_ASSERT(sizeof(UA_DataChangeTrigger) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_DATACHANGETRIGGER 73

/**
 * BuildInfo
 * ^^^^^^^^^
 */
typedef struct {
    UA_String productUri;
    UA_String manufacturerName;
    UA_String productName;
    UA_String softwareVersion;
    UA_String buildNumber;
    UA_DateTime buildDate;
} UA_BuildInfo;

#define UA_TYPES_BUILDINFO 74

/**
 * NodeClass
 * ^^^^^^^^^
 * A mask specifying the class of the node. */
typedef enum {
    UA_NODECLASS_UNSPECIFIED = 0,
    UA_NODECLASS_OBJECT = 1,
    UA_NODECLASS_VARIABLE = 2,
    UA_NODECLASS_METHOD = 4,
    UA_NODECLASS_OBJECTTYPE = 8,
    UA_NODECLASS_VARIABLETYPE = 16,
    UA_NODECLASS_REFERENCETYPE = 32,
    UA_NODECLASS_DATATYPE = 64,
    UA_NODECLASS_VIEW = 128,
    __UA_NODECLASS_FORCE32BIT = 0x7fffffff
} UA_NodeClass;
UA_STATIC_ASSERT(sizeof(UA_NodeClass) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_NODECLASS 75

/**
 * SubscriptionDiagnosticsDataType
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId sessionId;
    UA_UInt32 subscriptionId;
    UA_Byte priority;
    UA_Double publishingInterval;
    UA_UInt32 maxKeepAliveCount;
    UA_UInt32 maxLifetimeCount;
    UA_UInt32 maxNotificationsPerPublish;
    UA_Boolean publishingEnabled;
    UA_UInt32 modifyCount;
    UA_UInt32 enableCount;
    UA_UInt32 disableCount;
    UA_UInt32 republishRequestCount;
    UA_UInt32 republishMessageRequestCount;
    UA_UInt32 republishMessageCount;
    UA_UInt32 transferRequestCount;
    UA_UInt32 transferredToAltClientCount;
    UA_UInt32 transferredToSameClientCount;
    UA_UInt32 publishRequestCount;
    UA_UInt32 dataChangeNotificationsCount;
    UA_UInt32 eventNotificationsCount;
    UA_UInt32 notificationsCount;
    UA_UInt32 latePublishRequestCount;
    UA_UInt32 currentKeepAliveCount;
    UA_UInt32 currentLifetimeCount;
    UA_UInt32 unacknowledgedMessageCount;
    UA_UInt32 discardedMessageCount;
    UA_UInt32 monitoredItemCount;
    UA_UInt32 disabledMonitoredItemCount;
    UA_UInt32 monitoringQueueOverflowCount;
    UA_UInt32 nextSequenceNumber;
    UA_UInt32 eventQueueOverFlowCount;
} UA_SubscriptionDiagnosticsDataType;

#define UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE 76

/**
 * FilterOperand
 * ^^^^^^^^^^^^^
 */
typedef void * UA_FilterOperand;

#define UA_TYPES_FILTEROPERAND 77

/**
 * MonitoredItemNotification
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 clientHandle;
    UA_DataValue value;
} UA_MonitoredItemNotification;

#define UA_TYPES_MONITOREDITEMNOTIFICATION 78

/**
 * DeleteNodesItem
 * ^^^^^^^^^^^^^^^
 * A request to delete a node to the server address space. */
typedef struct {
    UA_NodeId nodeId;
    UA_Boolean deleteTargetReferences;
} UA_DeleteNodesItem;

#define UA_TYPES_DELETENODESITEM 79

/**
 * DeleteSubscriptionsRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t subscriptionIdsSize;
    UA_UInt32 *subscriptionIds;
} UA_DeleteSubscriptionsRequest;

#define UA_TYPES_DELETESUBSCRIPTIONSREQUEST 80

/**
 * SubscriptionAcknowledgement
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 subscriptionId;
    UA_UInt32 sequenceNumber;
} UA_SubscriptionAcknowledgement;

#define UA_TYPES_SUBSCRIPTIONACKNOWLEDGEMENT 81

/**
 * ReadValueId
 * ^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId nodeId;
    UA_UInt32 attributeId;
    UA_String indexRange;
    UA_QualifiedName dataEncoding;
} UA_ReadValueId;

#define UA_TYPES_READVALUEID 82

/**
 * DataTypeAttributes
 * ^^^^^^^^^^^^^^^^^^
 * The attributes for a data type node. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean isAbstract;
} UA_DataTypeAttributes;

#define UA_TYPES_DATATYPEATTRIBUTES 83

/**
 * ResponseHeader
 * ^^^^^^^^^^^^^^
 * The header passed with every server response. */
typedef struct {
    UA_DateTime timestamp;
    UA_UInt32 requestHandle;
    UA_StatusCode serviceResult;
    UA_DiagnosticInfo serviceDiagnostics;
    size_t stringTableSize;
    UA_String *stringTable;
    UA_ExtensionObject additionalHeader;
} UA_ResponseHeader;

#define UA_TYPES_RESPONSEHEADER 84

/**
 * DeleteMonitoredItemsRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    size_t monitoredItemIdsSize;
    UA_UInt32 *monitoredItemIds;
} UA_DeleteMonitoredItemsRequest;

#define UA_TYPES_DELETEMONITOREDITEMSREQUEST 85

/**
 * ViewDescription
 * ^^^^^^^^^^^^^^^
 * The view to browse. */
typedef struct {
    UA_NodeId viewId;
    UA_DateTime timestamp;
    UA_UInt32 viewVersion;
} UA_ViewDescription;

#define UA_TYPES_VIEWDESCRIPTION 86

/**
 * ServerOnNetwork
 * ^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 recordId;
    UA_String serverName;
    UA_String discoveryUrl;
    size_t serverCapabilitiesSize;
    UA_String *serverCapabilities;
} UA_ServerOnNetwork;

#define UA_TYPES_SERVERONNETWORK 87

/**
 * DeleteMonitoredItemsResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_DeleteMonitoredItemsResponse;

#define UA_TYPES_DELETEMONITOREDITEMSRESPONSE 88

/**
 * FindServersOnNetworkResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    UA_DateTime lastCounterResetTime;
    size_t serversSize;
    UA_ServerOnNetwork *servers;
} UA_FindServersOnNetworkResponse;

#define UA_TYPES_FINDSERVERSONNETWORKRESPONSE 89

/**
 * RelativePath
 * ^^^^^^^^^^^^
 * A relative path constructed from reference types and browse names. */
typedef struct {
    size_t elementsSize;
    UA_RelativePathElement *elements;
} UA_RelativePath;

#define UA_TYPES_RELATIVEPATH 90

/**
 * RegisterNodesRequest
 * ^^^^^^^^^^^^^^^^^^^^
 * Registers one or more nodes for repeated use within a session. */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t nodesToRegisterSize;
    UA_NodeId *nodesToRegister;
} UA_RegisterNodesRequest;

#define UA_TYPES_REGISTERNODESREQUEST 91

/**
 * AggregateConfiguration
 * ^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_Boolean useServerCapabilitiesDefaults;
    UA_Boolean treatUncertainAsBad;
    UA_Byte percentDataBad;
    UA_Byte percentDataGood;
    UA_Boolean useSlopedExtrapolation;
} UA_AggregateConfiguration;

#define UA_TYPES_AGGREGATECONFIGURATION 92

/**
 * DeleteNodesRequest
 * ^^^^^^^^^^^^^^^^^^
 * Delete one or more nodes from the server address space. */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t nodesToDeleteSize;
    UA_DeleteNodesItem *nodesToDelete;
} UA_DeleteNodesRequest;

#define UA_TYPES_DELETENODESREQUEST 93

/**
 * PublishResponse
 * ^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    UA_UInt32 subscriptionId;
    size_t availableSequenceNumbersSize;
    UA_UInt32 *availableSequenceNumbers;
    UA_Boolean moreNotifications;
    UA_NotificationMessage notificationMessage;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_PublishResponse;

#define UA_TYPES_PUBLISHRESPONSE 94

/**
 * MonitoredItemModifyRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 monitoredItemId;
    UA_MonitoringParameters requestedParameters;
} UA_MonitoredItemModifyRequest;

#define UA_TYPES_MONITOREDITEMMODIFYREQUEST 95

/**
 * ServiceCounterDataType
 * ^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 totalCount;
    UA_UInt32 errorCount;
} UA_ServiceCounterDataType;

#define UA_TYPES_SERVICECOUNTERDATATYPE 96

/**
 * ModelChangeStructureDataType
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId affected;
    UA_NodeId affectedType;
    UA_Byte verb;
} UA_ModelChangeStructureDataType;

#define UA_TYPES_MODELCHANGESTRUCTUREDATATYPE 97

/**
 * UserNameIdentityToken
 * ^^^^^^^^^^^^^^^^^^^^^
 * A token representing a user identified by a user name and password. */
typedef struct {
    UA_String policyId;
    UA_String userName;
    UA_ByteString password;
    UA_String encryptionAlgorithm;
} UA_UserNameIdentityToken;

#define UA_TYPES_USERNAMEIDENTITYTOKEN 98

/**
 * IdType
 * ^^^^^^
 * The type of identifier used in a node id. */
typedef enum {
    UA_IDTYPE_NUMERIC = 0,
    UA_IDTYPE_STRING = 1,
    UA_IDTYPE_GUID = 2,
    UA_IDTYPE_OPAQUE = 3,
    __UA_IDTYPE_FORCE32BIT = 0x7fffffff
} UA_IdType;
UA_STATIC_ASSERT(sizeof(UA_IdType) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_IDTYPE 99

/**
 * UserTokenType
 * ^^^^^^^^^^^^^
 * The possible user token types. */
typedef enum {
    UA_USERTOKENTYPE_ANONYMOUS = 0,
    UA_USERTOKENTYPE_USERNAME = 1,
    UA_USERTOKENTYPE_CERTIFICATE = 2,
    UA_USERTOKENTYPE_ISSUEDTOKEN = 3,
    __UA_USERTOKENTYPE_FORCE32BIT = 0x7fffffff
} UA_UserTokenType;
UA_STATIC_ASSERT(sizeof(UA_UserTokenType) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_USERTOKENTYPE 100

/**
 * SetTriggeringResponse
 * ^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t addResultsSize;
    UA_StatusCode *addResults;
    size_t addDiagnosticInfosSize;
    UA_DiagnosticInfo *addDiagnosticInfos;
    size_t removeResultsSize;
    UA_StatusCode *removeResults;
    size_t removeDiagnosticInfosSize;
    UA_DiagnosticInfo *removeDiagnosticInfos;
} UA_SetTriggeringResponse;

#define UA_TYPES_SETTRIGGERINGRESPONSE 101

/**
 * TimeZoneDataType
 * ^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_Int16 offset;
    UA_Boolean daylightSavingInOffset;
} UA_TimeZoneDataType;

#define UA_TYPES_TIMEZONEDATATYPE 102

/**
 * ActivateSessionRequest
 * ^^^^^^^^^^^^^^^^^^^^^^
 * Activates a session with the server. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_SignatureData clientSignature;
    size_t clientSoftwareCertificatesSize;
    UA_SignedSoftwareCertificate *clientSoftwareCertificates;
    size_t localeIdsSize;
    UA_String *localeIds;
    UA_ExtensionObject userIdentityToken;
    UA_SignatureData userTokenSignature;
} UA_ActivateSessionRequest;

#define UA_TYPES_ACTIVATESESSIONREQUEST 103

/**
 * OpenSecureChannelResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 * Creates a secure channel with a server. */
typedef struct {
    UA_ResponseHeader responseHeader;
    UA_UInt32 serverProtocolVersion;
    UA_ChannelSecurityToken securityToken;
    UA_ByteString serverNonce;
} UA_OpenSecureChannelResponse;

#define UA_TYPES_OPENSECURECHANNELRESPONSE 104

/**
 * ApplicationType
 * ^^^^^^^^^^^^^^^
 * The types of applications. */
typedef enum {
    UA_APPLICATIONTYPE_SERVER = 0,
    UA_APPLICATIONTYPE_CLIENT = 1,
    UA_APPLICATIONTYPE_CLIENTANDSERVER = 2,
    UA_APPLICATIONTYPE_DISCOVERYSERVER = 3,
    __UA_APPLICATIONTYPE_FORCE32BIT = 0x7fffffff
} UA_ApplicationType;
UA_STATIC_ASSERT(sizeof(UA_ApplicationType) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_APPLICATIONTYPE 105

/**
 * ServerState
 * ^^^^^^^^^^^
 */
typedef enum {
    UA_SERVERSTATE_RUNNING = 0,
    UA_SERVERSTATE_FAILED = 1,
    UA_SERVERSTATE_NOCONFIGURATION = 2,
    UA_SERVERSTATE_SUSPENDED = 3,
    UA_SERVERSTATE_SHUTDOWN = 4,
    UA_SERVERSTATE_TEST = 5,
    UA_SERVERSTATE_COMMUNICATIONFAULT = 6,
    UA_SERVERSTATE_UNKNOWN = 7,
    __UA_SERVERSTATE_FORCE32BIT = 0x7fffffff
} UA_ServerState;
UA_STATIC_ASSERT(sizeof(UA_ServerState) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_SERVERSTATE 106

/**
 * QueryNextResponse
 * ^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t queryDataSetsSize;
    UA_QueryDataSet *queryDataSets;
    UA_ByteString revisedContinuationPoint;
} UA_QueryNextResponse;

#define UA_TYPES_QUERYNEXTRESPONSE 107

/**
 * DiscoveryConfiguration
 * ^^^^^^^^^^^^^^^^^^^^^^
 * A base type for discovery configuration information. */
typedef void * UA_DiscoveryConfiguration;

#define UA_TYPES_DISCOVERYCONFIGURATION 108

/**
 * ActivateSessionResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^
 * Activates a session with the server. */
typedef struct {
    UA_ResponseHeader responseHeader;
    UA_ByteString serverNonce;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_ActivateSessionResponse;

#define UA_TYPES_ACTIVATESESSIONRESPONSE 109

/**
 * EndpointUrlListDataType
 * ^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    size_t endpointUrlListSize;
    UA_String *endpointUrlList;
} UA_EndpointUrlListDataType;

#define UA_TYPES_ENDPOINTURLLISTDATATYPE 110

/**
 * FilterOperator
 * ^^^^^^^^^^^^^^
 */
typedef enum {
    UA_FILTEROPERATOR_EQUALS = 0,
    UA_FILTEROPERATOR_ISNULL = 1,
    UA_FILTEROPERATOR_GREATERTHAN = 2,
    UA_FILTEROPERATOR_LESSTHAN = 3,
    UA_FILTEROPERATOR_GREATERTHANOREQUAL = 4,
    UA_FILTEROPERATOR_LESSTHANOREQUAL = 5,
    UA_FILTEROPERATOR_LIKE = 6,
    UA_FILTEROPERATOR_NOT = 7,
    UA_FILTEROPERATOR_BETWEEN = 8,
    UA_FILTEROPERATOR_INLIST = 9,
    UA_FILTEROPERATOR_AND = 10,
    UA_FILTEROPERATOR_OR = 11,
    UA_FILTEROPERATOR_CAST = 12,
    UA_FILTEROPERATOR_INVIEW = 13,
    UA_FILTEROPERATOR_OFTYPE = 14,
    UA_FILTEROPERATOR_RELATEDTO = 15,
    UA_FILTEROPERATOR_BITWISEAND = 16,
    UA_FILTEROPERATOR_BITWISEOR = 17,
    __UA_FILTEROPERATOR_FORCE32BIT = 0x7fffffff
} UA_FilterOperator;
UA_STATIC_ASSERT(sizeof(UA_FilterOperator) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_FILTEROPERATOR 111

/**
 * QueryNextRequest
 * ^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_Boolean releaseContinuationPoint;
    UA_ByteString continuationPoint;
} UA_QueryNextRequest;

#define UA_TYPES_QUERYNEXTREQUEST 112

/**
 * WriteResponse
 * ^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_WriteResponse;

#define UA_TYPES_WRITERESPONSE 113

/**
 * BrowseNextRequest
 * ^^^^^^^^^^^^^^^^^
 * Continues one or more browse operations. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_Boolean releaseContinuationPoints;
    size_t continuationPointsSize;
    UA_ByteString *continuationPoints;
} UA_BrowseNextRequest;

#define UA_TYPES_BROWSENEXTREQUEST 114

/**
 * CreateSubscriptionRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_Double requestedPublishingInterval;
    UA_UInt32 requestedLifetimeCount;
    UA_UInt32 requestedMaxKeepAliveCount;
    UA_UInt32 maxNotificationsPerPublish;
    UA_Boolean publishingEnabled;
    UA_Byte priority;
} UA_CreateSubscriptionRequest;

#define UA_TYPES_CREATESUBSCRIPTIONREQUEST 115

/**
 * VariableTypeAttributes
 * ^^^^^^^^^^^^^^^^^^^^^^
 * The attributes for a variable type node. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Variant value;
    UA_NodeId dataType;
    UA_Int32 valueRank;
    size_t arrayDimensionsSize;
    UA_UInt32 *arrayDimensions;
    UA_Boolean isAbstract;
} UA_VariableTypeAttributes;

#define UA_TYPES_VARIABLETYPEATTRIBUTES 116

/**
 * BrowsePathResult
 * ^^^^^^^^^^^^^^^^
 * The result of a translate opearation. */
typedef struct {
    UA_StatusCode statusCode;
    size_t targetsSize;
    UA_BrowsePathTarget *targets;
} UA_BrowsePathResult;

#define UA_TYPES_BROWSEPATHRESULT 117

/**
 * ModifySubscriptionResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    UA_Double revisedPublishingInterval;
    UA_UInt32 revisedLifetimeCount;
    UA_UInt32 revisedMaxKeepAliveCount;
} UA_ModifySubscriptionResponse;

#define UA_TYPES_MODIFYSUBSCRIPTIONRESPONSE 118

/**
 * RedundantServerDataType
 * ^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_String serverId;
    UA_Byte serviceLevel;
    UA_ServerState serverState;
} UA_RedundantServerDataType;

#define UA_TYPES_REDUNDANTSERVERDATATYPE 119

/**
 * RegisterNodesResponse
 * ^^^^^^^^^^^^^^^^^^^^^
 * Registers one or more nodes for repeated use within a session. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t registeredNodeIdsSize;
    UA_NodeId *registeredNodeIds;
} UA_RegisterNodesResponse;

#define UA_TYPES_REGISTERNODESRESPONSE 120

/**
 * CloseSessionRequest
 * ^^^^^^^^^^^^^^^^^^^
 * Closes a session with the server. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_Boolean deleteSubscriptions;
} UA_CloseSessionRequest;

#define UA_TYPES_CLOSESESSIONREQUEST 121

/**
 * ModifyMonitoredItemsResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_MonitoredItemModifyResult *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_ModifyMonitoredItemsResponse;

#define UA_TYPES_MODIFYMONITOREDITEMSRESPONSE 122

/**
 * ModifySubscriptionRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    UA_Double requestedPublishingInterval;
    UA_UInt32 requestedLifetimeCount;
    UA_UInt32 requestedMaxKeepAliveCount;
    UA_UInt32 maxNotificationsPerPublish;
    UA_Byte priority;
} UA_ModifySubscriptionRequest;

#define UA_TYPES_MODIFYSUBSCRIPTIONREQUEST 123

/**
 * ServerDiagnosticsSummaryDataType
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_UInt32 serverViewCount;
    UA_UInt32 currentSessionCount;
    UA_UInt32 cumulatedSessionCount;
    UA_UInt32 securityRejectedSessionCount;
    UA_UInt32 rejectedSessionCount;
    UA_UInt32 sessionTimeoutCount;
    UA_UInt32 sessionAbortCount;
    UA_UInt32 currentSubscriptionCount;
    UA_UInt32 cumulatedSubscriptionCount;
    UA_UInt32 publishingIntervalCount;
    UA_UInt32 securityRejectedRequestsCount;
    UA_UInt32 rejectedRequestsCount;
} UA_ServerDiagnosticsSummaryDataType;

#define UA_TYPES_SERVERDIAGNOSTICSSUMMARYDATATYPE 124

/**
 * UserTokenPolicy
 * ^^^^^^^^^^^^^^^
 * Describes a user token that can be used with a server. */
typedef struct {
    UA_String policyId;
    UA_UserTokenType tokenType;
    UA_String issuedTokenType;
    UA_String issuerEndpointUrl;
    UA_String securityPolicyUri;
} UA_UserTokenPolicy;

#define UA_TYPES_USERTOKENPOLICY 125

/**
 * ReferenceTypeAttributes
 * ^^^^^^^^^^^^^^^^^^^^^^^
 * The attributes for a reference type node. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Boolean isAbstract;
    UA_Boolean symmetric;
    UA_LocalizedText inverseName;
} UA_ReferenceTypeAttributes;

#define UA_TYPES_REFERENCETYPEATTRIBUTES 126

/**
 * BrowsePath
 * ^^^^^^^^^^
 * A request to translate a path into a node id. */
typedef struct {
    UA_NodeId startingNode;
    UA_RelativePath relativePath;
} UA_BrowsePath;

#define UA_TYPES_BROWSEPATH 127

/**
 * SetMonitoringModeRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    UA_MonitoringMode monitoringMode;
    size_t monitoredItemIdsSize;
    UA_UInt32 *monitoredItemIds;
} UA_SetMonitoringModeRequest;

#define UA_TYPES_SETMONITORINGMODEREQUEST 128

/**
 * UnregisterNodesResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^
 * Unregisters one or more previously registered nodes. */
typedef struct {
    UA_ResponseHeader responseHeader;
} UA_UnregisterNodesResponse;

#define UA_TYPES_UNREGISTERNODESRESPONSE 129

/**
 * WriteRequest
 * ^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t nodesToWriteSize;
    UA_WriteValue *nodesToWrite;
} UA_WriteRequest;

#define UA_TYPES_WRITEREQUEST 130

/**
 * ObjectAttributes
 * ^^^^^^^^^^^^^^^^
 * The attributes for an object node. */
typedef struct {
    UA_UInt32 specifiedAttributes;
    UA_LocalizedText displayName;
    UA_LocalizedText description;
    UA_UInt32 writeMask;
    UA_UInt32 userWriteMask;
    UA_Byte eventNotifier;
} UA_ObjectAttributes;

#define UA_TYPES_OBJECTATTRIBUTES 131

/**
 * BrowseResultMask
 * ^^^^^^^^^^^^^^^^
 * A bit mask which specifies what should be returned in a browse response. */
typedef enum {
    UA_BROWSERESULTMASK_NONE = 0,
    UA_BROWSERESULTMASK_REFERENCETYPEID = 1,
    UA_BROWSERESULTMASK_ISFORWARD = 2,
    UA_BROWSERESULTMASK_NODECLASS = 4,
    UA_BROWSERESULTMASK_BROWSENAME = 8,
    UA_BROWSERESULTMASK_DISPLAYNAME = 16,
    UA_BROWSERESULTMASK_TYPEDEFINITION = 32,
    UA_BROWSERESULTMASK_ALL = 63,
    UA_BROWSERESULTMASK_REFERENCETYPEINFO = 3,
    UA_BROWSERESULTMASK_TARGETINFO = 60,
    __UA_BROWSERESULTMASK_FORCE32BIT = 0x7fffffff
} UA_BrowseResultMask;
UA_STATIC_ASSERT(sizeof(UA_BrowseResultMask) == sizeof(UA_Int32), enum_must_be_32bit);

#define UA_TYPES_BROWSERESULTMASK 132

/**
 * BrowseDescription
 * ^^^^^^^^^^^^^^^^^
 * A request to browse the the references from a node. */
typedef struct {
    UA_NodeId nodeId;
    UA_BrowseDirection browseDirection;
    UA_NodeId referenceTypeId;
    UA_Boolean includeSubtypes;
    UA_UInt32 nodeClassMask;
    UA_UInt32 resultMask;
} UA_BrowseDescription;

#define UA_TYPES_BROWSEDESCRIPTION 133

/**
 * SetTriggeringRequest
 * ^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    UA_UInt32 triggeringItemId;
    size_t linksToAddSize;
    UA_UInt32 *linksToAdd;
    size_t linksToRemoveSize;
    UA_UInt32 *linksToRemove;
} UA_SetTriggeringRequest;

#define UA_TYPES_SETTRIGGERINGREQUEST 134

/**
 * SessionSecurityDiagnosticsDataType
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId sessionId;
    UA_String clientUserIdOfSession;
    size_t clientUserIdHistorySize;
    UA_String *clientUserIdHistory;
    UA_String authenticationMechanism;
    UA_String encoding;
    UA_String transportProtocol;
    UA_MessageSecurityMode securityMode;
    UA_String securityPolicyUri;
    UA_ByteString clientCertificate;
} UA_SessionSecurityDiagnosticsDataType;

#define UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE 135

/**
 * RepublishRequest
 * ^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    UA_UInt32 retransmitSequenceNumber;
} UA_RepublishRequest;

#define UA_TYPES_REPUBLISHREQUEST 136

/**
 * GetEndpointsRequest
 * ^^^^^^^^^^^^^^^^^^^
 * Gets the endpoints used by the server. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_String endpointUrl;
    size_t localeIdsSize;
    UA_String *localeIds;
    size_t profileUrisSize;
    UA_String *profileUris;
} UA_GetEndpointsRequest;

#define UA_TYPES_GETENDPOINTSREQUEST 137

/**
 * PublishRequest
 * ^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t subscriptionAcknowledgementsSize;
    UA_SubscriptionAcknowledgement *subscriptionAcknowledgements;
} UA_PublishRequest;

#define UA_TYPES_PUBLISHREQUEST 138

/**
 * DeleteSubscriptionsResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_DeleteSubscriptionsResponse;

#define UA_TYPES_DELETESUBSCRIPTIONSRESPONSE 139

/**
 * AddNodesResponse
 * ^^^^^^^^^^^^^^^^
 * Adds one or more nodes to the server address space. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_AddNodesResult *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_AddNodesResponse;

#define UA_TYPES_ADDNODESRESPONSE 140

/**
 * DataChangeNotification
 * ^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    size_t monitoredItemsSize;
    UA_MonitoredItemNotification *monitoredItems;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_DataChangeNotification;

#define UA_TYPES_DATACHANGENOTIFICATION 141

/**
 * CloseSecureChannelResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 * Closes a secure channel. */
typedef struct {
    UA_ResponseHeader responseHeader;
} UA_CloseSecureChannelResponse;

#define UA_TYPES_CLOSESECURECHANNELRESPONSE 142

/**
 * ModifyMonitoredItemsRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    UA_TimestampsToReturn timestampsToReturn;
    size_t itemsToModifySize;
    UA_MonitoredItemModifyRequest *itemsToModify;
} UA_ModifyMonitoredItemsRequest;

#define UA_TYPES_MODIFYMONITOREDITEMSREQUEST 143

/**
 * SetMonitoringModeResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_SetMonitoringModeResponse;

#define UA_TYPES_SETMONITORINGMODERESPONSE 144

/**
 * FindServersRequest
 * ^^^^^^^^^^^^^^^^^^
 * Finds the servers known to the discovery server. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_String endpointUrl;
    size_t localeIdsSize;
    UA_String *localeIds;
    size_t serverUrisSize;
    UA_String *serverUris;
} UA_FindServersRequest;

#define UA_TYPES_FINDSERVERSREQUEST 145

/**
 * ReferenceDescription
 * ^^^^^^^^^^^^^^^^^^^^
 * The description of a reference. */
typedef struct {
    UA_NodeId referenceTypeId;
    UA_Boolean isForward;
    UA_ExpandedNodeId nodeId;
    UA_QualifiedName browseName;
    UA_LocalizedText displayName;
    UA_NodeClass nodeClass;
    UA_ExpandedNodeId typeDefinition;
} UA_ReferenceDescription;

#define UA_TYPES_REFERENCEDESCRIPTION 146

/**
 * SetPublishingModeResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_SetPublishingModeResponse;

#define UA_TYPES_SETPUBLISHINGMODERESPONSE 147

/**
 * ContentFilterResult
 * ^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    size_t elementResultsSize;
    UA_ContentFilterElementResult *elementResults;
    size_t elementDiagnosticInfosSize;
    UA_DiagnosticInfo *elementDiagnosticInfos;
} UA_ContentFilterResult;

#define UA_TYPES_CONTENTFILTERRESULT 148

/**
 * RegisterServerResponse
 * ^^^^^^^^^^^^^^^^^^^^^^
 * Registers a server with the discovery server. */
typedef struct {
    UA_ResponseHeader responseHeader;
} UA_RegisterServerResponse;

#define UA_TYPES_REGISTERSERVERRESPONSE 149

/**
 * AddReferencesItem
 * ^^^^^^^^^^^^^^^^^
 * A request to add a reference to the server address space. */
typedef struct {
    UA_NodeId sourceNodeId;
    UA_NodeId referenceTypeId;
    UA_Boolean isForward;
    UA_String targetServerUri;
    UA_ExpandedNodeId targetNodeId;
    UA_NodeClass targetNodeClass;
} UA_AddReferencesItem;

#define UA_TYPES_ADDREFERENCESITEM 150

/**
 * QueryDataDescription
 * ^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RelativePath relativePath;
    UA_UInt32 attributeId;
    UA_String indexRange;
} UA_QueryDataDescription;

#define UA_TYPES_QUERYDATADESCRIPTION 151

/**
 * CreateSubscriptionResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    UA_UInt32 subscriptionId;
    UA_Double revisedPublishingInterval;
    UA_UInt32 revisedLifetimeCount;
    UA_UInt32 revisedMaxKeepAliveCount;
} UA_CreateSubscriptionResponse;

#define UA_TYPES_CREATESUBSCRIPTIONRESPONSE 152

/**
 * NetworkGroupDataType
 * ^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_String serverUri;
    size_t networkPathsSize;
    UA_EndpointUrlListDataType *networkPaths;
} UA_NetworkGroupDataType;

#define UA_TYPES_NETWORKGROUPDATATYPE 153

/**
 * DeleteReferencesResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^
 * Delete one or more references from the server address space. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_DeleteReferencesResponse;

#define UA_TYPES_DELETEREFERENCESRESPONSE 154

/**
 * CreateMonitoredItemsResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_MonitoredItemCreateResult *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_CreateMonitoredItemsResponse;

#define UA_TYPES_CREATEMONITOREDITEMSRESPONSE 155

/**
 * CallResponse
 * ^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_CallMethodResult *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_CallResponse;

#define UA_TYPES_CALLRESPONSE 156

/**
 * DeleteNodesResponse
 * ^^^^^^^^^^^^^^^^^^^
 * Delete one or more nodes from the server address space. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_DeleteNodesResponse;

#define UA_TYPES_DELETENODESRESPONSE 157

/**
 * RepublishResponse
 * ^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    UA_NotificationMessage notificationMessage;
} UA_RepublishResponse;

#define UA_TYPES_REPUBLISHRESPONSE 158

/**
 * MonitoredItemCreateRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ReadValueId itemToMonitor;
    UA_MonitoringMode monitoringMode;
    UA_MonitoringParameters requestedParameters;
} UA_MonitoredItemCreateRequest;

#define UA_TYPES_MONITOREDITEMCREATEREQUEST 159

/**
 * DeleteReferencesRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^
 * Delete one or more references from the server address space. */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t referencesToDeleteSize;
    UA_DeleteReferencesItem *referencesToDelete;
} UA_DeleteReferencesRequest;

#define UA_TYPES_DELETEREFERENCESREQUEST 160

/**
 * ReadResponse
 * ^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_DataValue *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_ReadResponse;

#define UA_TYPES_READRESPONSE 161

/**
 * AddReferencesRequest
 * ^^^^^^^^^^^^^^^^^^^^
 * Adds one or more references to the server address space. */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t referencesToAddSize;
    UA_AddReferencesItem *referencesToAdd;
} UA_AddReferencesRequest;

#define UA_TYPES_ADDREFERENCESREQUEST 162

/**
 * ReadRequest
 * ^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_Double maxAge;
    UA_TimestampsToReturn timestampsToReturn;
    size_t nodesToReadSize;
    UA_ReadValueId *nodesToRead;
} UA_ReadRequest;

#define UA_TYPES_READREQUEST 163

/**
 * OpenSecureChannelRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^
 * Creates a secure channel with a server. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 clientProtocolVersion;
    UA_SecurityTokenRequestType requestType;
    UA_MessageSecurityMode securityMode;
    UA_ByteString clientNonce;
    UA_UInt32 requestedLifetime;
} UA_OpenSecureChannelRequest;

#define UA_TYPES_OPENSECURECHANNELREQUEST 164

/**
 * RegisterServer2Response
 * ^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t configurationResultsSize;
    UA_StatusCode *configurationResults;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_RegisterServer2Response;

#define UA_TYPES_REGISTERSERVER2RESPONSE 165

/**
 * AddNodesItem
 * ^^^^^^^^^^^^
 * A request to add a node to the server address space. */
typedef struct {
    UA_ExpandedNodeId parentNodeId;
    UA_NodeId referenceTypeId;
    UA_ExpandedNodeId requestedNewNodeId;
    UA_QualifiedName browseName;
    UA_NodeClass nodeClass;
    UA_ExtensionObject nodeAttributes;
    UA_ExpandedNodeId typeDefinition;
} UA_AddNodesItem;

#define UA_TYPES_ADDNODESITEM 166

/**
 * NodeTypeDescription
 * ^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ExpandedNodeId typeDefinitionNode;
    UA_Boolean includeSubTypes;
    size_t dataToReturnSize;
    UA_QueryDataDescription *dataToReturn;
} UA_NodeTypeDescription;

#define UA_TYPES_NODETYPEDESCRIPTION 167

/**
 * ServerStatusDataType
 * ^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_DateTime startTime;
    UA_DateTime currentTime;
    UA_ServerState state;
    UA_BuildInfo buildInfo;
    UA_UInt32 secondsTillShutdown;
    UA_LocalizedText shutdownReason;
} UA_ServerStatusDataType;

#define UA_TYPES_SERVERSTATUSDATATYPE 168

/**
 * AttributeOperand
 * ^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId nodeId;
    UA_String alias;
    UA_RelativePath browsePath;
    UA_UInt32 attributeId;
    UA_String indexRange;
} UA_AttributeOperand;

#define UA_TYPES_ATTRIBUTEOPERAND 169

/**
 * AddReferencesResponse
 * ^^^^^^^^^^^^^^^^^^^^^
 * Adds one or more references to the server address space. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_StatusCode *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_AddReferencesResponse;

#define UA_TYPES_ADDREFERENCESRESPONSE 170

/**
 * EventFilterResult
 * ^^^^^^^^^^^^^^^^^
 */
typedef struct {
    size_t selectClauseResultsSize;
    UA_StatusCode *selectClauseResults;
    size_t selectClauseDiagnosticInfosSize;
    UA_DiagnosticInfo *selectClauseDiagnosticInfos;
    UA_ContentFilterResult whereClauseResult;
} UA_EventFilterResult;

#define UA_TYPES_EVENTFILTERRESULT 171

/**
 * TranslateBrowsePathsToNodeIdsResponse
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * Translates one or more paths in the server address space. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_BrowsePathResult *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_TranslateBrowsePathsToNodeIdsResponse;

#define UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE 172

/**
 * DataChangeFilter
 * ^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_DataChangeTrigger trigger;
    UA_UInt32 deadbandType;
    UA_Double deadbandValue;
} UA_DataChangeFilter;

#define UA_TYPES_DATACHANGEFILTER 173

/**
 * ContentFilterElement
 * ^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_FilterOperator filterOperator;
    size_t filterOperandsSize;
    UA_ExtensionObject *filterOperands;
} UA_ContentFilterElement;

#define UA_TYPES_CONTENTFILTERELEMENT 174

/**
 * TranslateBrowsePathsToNodeIdsRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 * Translates one or more paths in the server address space. */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t browsePathsSize;
    UA_BrowsePath *browsePaths;
} UA_TranslateBrowsePathsToNodeIdsRequest;

#define UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSREQUEST 175

/**
 * CloseSessionResponse
 * ^^^^^^^^^^^^^^^^^^^^
 * Closes a session with the server. */
typedef struct {
    UA_ResponseHeader responseHeader;
} UA_CloseSessionResponse;

#define UA_TYPES_CLOSESESSIONRESPONSE 176

/**
 * ApplicationDescription
 * ^^^^^^^^^^^^^^^^^^^^^^
 * Describes an application and how to find it. */
typedef struct {
    UA_String applicationUri;
    UA_String productUri;
    UA_LocalizedText applicationName;
    UA_ApplicationType applicationType;
    UA_String gatewayServerUri;
    UA_String discoveryProfileUri;
    size_t discoveryUrlsSize;
    UA_String *discoveryUrls;
} UA_ApplicationDescription;

#define UA_TYPES_APPLICATIONDESCRIPTION 177

/**
 * SessionDiagnosticsDataType
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_NodeId sessionId;
    UA_String sessionName;
    UA_ApplicationDescription clientDescription;
    UA_String serverUri;
    UA_String endpointUrl;
    size_t localeIdsSize;
    UA_String *localeIds;
    UA_Double actualSessionTimeout;
    UA_UInt32 maxResponseMessageSize;
    UA_DateTime clientConnectionTime;
    UA_DateTime clientLastContactTime;
    UA_UInt32 currentSubscriptionsCount;
    UA_UInt32 currentMonitoredItemsCount;
    UA_UInt32 currentPublishRequestsInQueue;
    UA_ServiceCounterDataType totalRequestCount;
    UA_UInt32 unauthorizedRequestCount;
    UA_ServiceCounterDataType readCount;
    UA_ServiceCounterDataType historyReadCount;
    UA_ServiceCounterDataType writeCount;
    UA_ServiceCounterDataType historyUpdateCount;
    UA_ServiceCounterDataType callCount;
    UA_ServiceCounterDataType createMonitoredItemsCount;
    UA_ServiceCounterDataType modifyMonitoredItemsCount;
    UA_ServiceCounterDataType setMonitoringModeCount;
    UA_ServiceCounterDataType setTriggeringCount;
    UA_ServiceCounterDataType deleteMonitoredItemsCount;
    UA_ServiceCounterDataType createSubscriptionCount;
    UA_ServiceCounterDataType modifySubscriptionCount;
    UA_ServiceCounterDataType setPublishingModeCount;
    UA_ServiceCounterDataType publishCount;
    UA_ServiceCounterDataType republishCount;
    UA_ServiceCounterDataType transferSubscriptionsCount;
    UA_ServiceCounterDataType deleteSubscriptionsCount;
    UA_ServiceCounterDataType addNodesCount;
    UA_ServiceCounterDataType addReferencesCount;
    UA_ServiceCounterDataType deleteNodesCount;
    UA_ServiceCounterDataType deleteReferencesCount;
    UA_ServiceCounterDataType browseCount;
    UA_ServiceCounterDataType browseNextCount;
    UA_ServiceCounterDataType translateBrowsePathsToNodeIdsCount;
    UA_ServiceCounterDataType queryFirstCount;
    UA_ServiceCounterDataType queryNextCount;
    UA_ServiceCounterDataType registerNodesCount;
    UA_ServiceCounterDataType unregisterNodesCount;
} UA_SessionDiagnosticsDataType;

#define UA_TYPES_SESSIONDIAGNOSTICSDATATYPE 178

/**
 * ServiceFault
 * ^^^^^^^^^^^^
 * The response returned by all services when there is a service level error. */
typedef struct {
    UA_ResponseHeader responseHeader;
} UA_ServiceFault;

#define UA_TYPES_SERVICEFAULT 179

/**
 * RegisteredServer
 * ^^^^^^^^^^^^^^^^
 * The information required to register a server with a discovery server. */
typedef struct {
    UA_String serverUri;
    UA_String productUri;
    size_t serverNamesSize;
    UA_LocalizedText *serverNames;
    UA_ApplicationType serverType;
    UA_String gatewayServerUri;
    size_t discoveryUrlsSize;
    UA_String *discoveryUrls;
    UA_String semaphoreFilePath;
    UA_Boolean isOnline;
} UA_RegisteredServer;

#define UA_TYPES_REGISTEREDSERVER 180

/**
 * AggregateFilter
 * ^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_DateTime startTime;
    UA_NodeId aggregateType;
    UA_Double processingInterval;
    UA_AggregateConfiguration aggregateConfiguration;
} UA_AggregateFilter;

#define UA_TYPES_AGGREGATEFILTER 181

/**
 * RegisterServerRequest
 * ^^^^^^^^^^^^^^^^^^^^^
 * Registers a server with the discovery server. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_RegisteredServer server;
} UA_RegisterServerRequest;

#define UA_TYPES_REGISTERSERVERREQUEST 182

/**
 * EndpointDescription
 * ^^^^^^^^^^^^^^^^^^^
 * The description of a endpoint that can be used to access a server. */
typedef struct {
    UA_String endpointUrl;
    UA_ApplicationDescription server;
    UA_ByteString serverCertificate;
    UA_MessageSecurityMode securityMode;
    UA_String securityPolicyUri;
    size_t userIdentityTokensSize;
    UA_UserTokenPolicy *userIdentityTokens;
    UA_String transportProfileUri;
    UA_Byte securityLevel;
} UA_EndpointDescription;

#define UA_TYPES_ENDPOINTDESCRIPTION 183

/**
 * CreateMonitoredItemsRequest
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_UInt32 subscriptionId;
    UA_TimestampsToReturn timestampsToReturn;
    size_t itemsToCreateSize;
    UA_MonitoredItemCreateRequest *itemsToCreate;
} UA_CreateMonitoredItemsRequest;

#define UA_TYPES_CREATEMONITOREDITEMSREQUEST 184

/**
 * ContentFilter
 * ^^^^^^^^^^^^^
 */
typedef struct {
    size_t elementsSize;
    UA_ContentFilterElement *elements;
} UA_ContentFilter;

#define UA_TYPES_CONTENTFILTER 185

/**
 * QueryFirstResponse
 * ^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t queryDataSetsSize;
    UA_QueryDataSet *queryDataSets;
    UA_ByteString continuationPoint;
    size_t parsingResultsSize;
    UA_ParsingResult *parsingResults;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
    UA_ContentFilterResult filterResult;
} UA_QueryFirstResponse;

#define UA_TYPES_QUERYFIRSTRESPONSE 186

/**
 * AddNodesRequest
 * ^^^^^^^^^^^^^^^
 * Adds one or more nodes to the server address space. */
typedef struct {
    UA_RequestHeader requestHeader;
    size_t nodesToAddSize;
    UA_AddNodesItem *nodesToAdd;
} UA_AddNodesRequest;

#define UA_TYPES_ADDNODESREQUEST 187

/**
 * BrowseRequest
 * ^^^^^^^^^^^^^
 * Browse the references for one or more nodes from the server address space. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_ViewDescription view;
    UA_UInt32 requestedMaxReferencesPerNode;
    size_t nodesToBrowseSize;
    UA_BrowseDescription *nodesToBrowse;
} UA_BrowseRequest;

#define UA_TYPES_BROWSEREQUEST 188

/**
 * BrowseResult
 * ^^^^^^^^^^^^
 * The result of a browse operation. */
typedef struct {
    UA_StatusCode statusCode;
    UA_ByteString continuationPoint;
    size_t referencesSize;
    UA_ReferenceDescription *references;
} UA_BrowseResult;

#define UA_TYPES_BROWSERESULT 189

/**
 * RegisterServer2Request
 * ^^^^^^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_RegisteredServer server;
    size_t discoveryConfigurationSize;
    UA_ExtensionObject *discoveryConfiguration;
} UA_RegisterServer2Request;

#define UA_TYPES_REGISTERSERVER2REQUEST 190

/**
 * CreateSessionRequest
 * ^^^^^^^^^^^^^^^^^^^^
 * Creates a new session with the server. */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_ApplicationDescription clientDescription;
    UA_String serverUri;
    UA_String endpointUrl;
    UA_String sessionName;
    UA_ByteString clientNonce;
    UA_ByteString clientCertificate;
    UA_Double requestedSessionTimeout;
    UA_UInt32 maxResponseMessageSize;
} UA_CreateSessionRequest;

#define UA_TYPES_CREATESESSIONREQUEST 191

/**
 * EventFilter
 * ^^^^^^^^^^^
 */
typedef struct {
    size_t selectClausesSize;
    UA_SimpleAttributeOperand *selectClauses;
    UA_ContentFilter whereClause;
} UA_EventFilter;

#define UA_TYPES_EVENTFILTER 192

/**
 * GetEndpointsResponse
 * ^^^^^^^^^^^^^^^^^^^^
 * Gets the endpoints used by the server. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t endpointsSize;
    UA_EndpointDescription *endpoints;
} UA_GetEndpointsResponse;

#define UA_TYPES_GETENDPOINTSRESPONSE 193

/**
 * FindServersResponse
 * ^^^^^^^^^^^^^^^^^^^
 * Finds the servers known to the discovery server. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t serversSize;
    UA_ApplicationDescription *servers;
} UA_FindServersResponse;

#define UA_TYPES_FINDSERVERSRESPONSE 194

/**
 * BrowseNextResponse
 * ^^^^^^^^^^^^^^^^^^
 * Continues one or more browse operations. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_BrowseResult *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_BrowseNextResponse;

#define UA_TYPES_BROWSENEXTRESPONSE 195

/**
 * BrowseResponse
 * ^^^^^^^^^^^^^^
 * Browse the references for one or more nodes from the server address space. */
typedef struct {
    UA_ResponseHeader responseHeader;
    size_t resultsSize;
    UA_BrowseResult *results;
    size_t diagnosticInfosSize;
    UA_DiagnosticInfo *diagnosticInfos;
} UA_BrowseResponse;

#define UA_TYPES_BROWSERESPONSE 196

/**
 * CreateSessionResponse
 * ^^^^^^^^^^^^^^^^^^^^^
 * Creates a new session with the server. */
typedef struct {
    UA_ResponseHeader responseHeader;
    UA_NodeId sessionId;
    UA_NodeId authenticationToken;
    UA_Double revisedSessionTimeout;
    UA_ByteString serverNonce;
    UA_ByteString serverCertificate;
    size_t serverEndpointsSize;
    UA_EndpointDescription *serverEndpoints;
    size_t serverSoftwareCertificatesSize;
    UA_SignedSoftwareCertificate *serverSoftwareCertificates;
    UA_SignatureData serverSignature;
    UA_UInt32 maxRequestMessageSize;
} UA_CreateSessionResponse;

#define UA_TYPES_CREATESESSIONRESPONSE 197

/**
 * QueryFirstRequest
 * ^^^^^^^^^^^^^^^^^
 */
typedef struct {
    UA_RequestHeader requestHeader;
    UA_ViewDescription view;
    size_t nodeTypesSize;
    UA_NodeTypeDescription *nodeTypes;
    UA_ContentFilter filter;
    UA_UInt32 maxDataSetsToReturn;
    UA_UInt32 maxReferencesToReturn;
} UA_QueryFirstRequest;

#define UA_TYPES_QUERYFIRSTREQUEST 198

/**
 * UtcTime
 * ^^^^^^^
 * A date/time value specified in Universal Coordinated Time (UTC). */
typedef UA_DateTime UA_UtcTime;

#define UA_TYPES_UTCTIME UA_TYPES_DATETIME

/**
 * LocaleId
 * ^^^^^^^^
 * An identifier for a user locale. */
typedef UA_String UA_LocaleId;

#define UA_TYPES_LOCALEID UA_TYPES_STRING

/**
 * Duration
 * ^^^^^^^^
 * A period of time measured in milliseconds. */
typedef UA_Double UA_Duration;

#define UA_TYPES_DURATION UA_TYPES_DOUBLE

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/build/src_generated/ua_types_generated_handling.h" ***********************************/

/* Generated from Opc.Ua.Types.bsd with script /home/travis/build/open62541/open62541/tools/generate_datatypes.py
 * on host travis-job-193db498-e14a-4886-911f-7172c9e50b7a by user travis at 2018-12-19 02:27:56 */


#ifdef __cplusplus
extern "C" {
#endif


#if defined(__GNUC__) && __GNUC__ >= 4 && __GNUC_MINOR__ >= 6
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wmissing-field-initializers"
# pragma GCC diagnostic ignored "-Wmissing-braces"
#endif


/* Boolean */
static UA_INLINE void
UA_Boolean_init(UA_Boolean *p) {
    memset(p, 0, sizeof(UA_Boolean));
}

static UA_INLINE UA_Boolean *
UA_Boolean_new(void) {
    return (UA_Boolean*)UA_new(&UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Boolean_copy(const UA_Boolean *src, UA_Boolean *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_Boolean_deleteMembers(UA_Boolean *p) { }

static UA_INLINE void
UA_Boolean_delete(UA_Boolean *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

/* SByte */
static UA_INLINE void
UA_SByte_init(UA_SByte *p) {
    memset(p, 0, sizeof(UA_SByte));
}

static UA_INLINE UA_SByte *
UA_SByte_new(void) {
    return (UA_SByte*)UA_new(&UA_TYPES[UA_TYPES_SBYTE]);
}

static UA_INLINE UA_StatusCode
UA_SByte_copy(const UA_SByte *src, UA_SByte *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_SByte_deleteMembers(UA_SByte *p) { }

static UA_INLINE void
UA_SByte_delete(UA_SByte *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SBYTE]);
}

/* Byte */
static UA_INLINE void
UA_Byte_init(UA_Byte *p) {
    memset(p, 0, sizeof(UA_Byte));
}

static UA_INLINE UA_Byte *
UA_Byte_new(void) {
    return (UA_Byte*)UA_new(&UA_TYPES[UA_TYPES_BYTE]);
}

static UA_INLINE UA_StatusCode
UA_Byte_copy(const UA_Byte *src, UA_Byte *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_Byte_deleteMembers(UA_Byte *p) { }

static UA_INLINE void
UA_Byte_delete(UA_Byte *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BYTE]);
}

/* Int16 */
static UA_INLINE void
UA_Int16_init(UA_Int16 *p) {
    memset(p, 0, sizeof(UA_Int16));
}

static UA_INLINE UA_Int16 *
UA_Int16_new(void) {
    return (UA_Int16*)UA_new(&UA_TYPES[UA_TYPES_INT16]);
}

static UA_INLINE UA_StatusCode
UA_Int16_copy(const UA_Int16 *src, UA_Int16 *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_Int16_deleteMembers(UA_Int16 *p) { }

static UA_INLINE void
UA_Int16_delete(UA_Int16 *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_INT16]);
}

/* UInt16 */
static UA_INLINE void
UA_UInt16_init(UA_UInt16 *p) {
    memset(p, 0, sizeof(UA_UInt16));
}

static UA_INLINE UA_UInt16 *
UA_UInt16_new(void) {
    return (UA_UInt16*)UA_new(&UA_TYPES[UA_TYPES_UINT16]);
}

static UA_INLINE UA_StatusCode
UA_UInt16_copy(const UA_UInt16 *src, UA_UInt16 *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_UInt16_deleteMembers(UA_UInt16 *p) { }

static UA_INLINE void
UA_UInt16_delete(UA_UInt16 *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_UINT16]);
}

/* Int32 */
static UA_INLINE void
UA_Int32_init(UA_Int32 *p) {
    memset(p, 0, sizeof(UA_Int32));
}

static UA_INLINE UA_Int32 *
UA_Int32_new(void) {
    return (UA_Int32*)UA_new(&UA_TYPES[UA_TYPES_INT32]);
}

static UA_INLINE UA_StatusCode
UA_Int32_copy(const UA_Int32 *src, UA_Int32 *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_Int32_deleteMembers(UA_Int32 *p) { }

static UA_INLINE void
UA_Int32_delete(UA_Int32 *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_INT32]);
}

/* UInt32 */
static UA_INLINE void
UA_UInt32_init(UA_UInt32 *p) {
    memset(p, 0, sizeof(UA_UInt32));
}

static UA_INLINE UA_UInt32 *
UA_UInt32_new(void) {
    return (UA_UInt32*)UA_new(&UA_TYPES[UA_TYPES_UINT32]);
}

static UA_INLINE UA_StatusCode
UA_UInt32_copy(const UA_UInt32 *src, UA_UInt32 *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_UInt32_deleteMembers(UA_UInt32 *p) { }

static UA_INLINE void
UA_UInt32_delete(UA_UInt32 *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_UINT32]);
}

/* Int64 */
static UA_INLINE void
UA_Int64_init(UA_Int64 *p) {
    memset(p, 0, sizeof(UA_Int64));
}

static UA_INLINE UA_Int64 *
UA_Int64_new(void) {
    return (UA_Int64*)UA_new(&UA_TYPES[UA_TYPES_INT64]);
}

static UA_INLINE UA_StatusCode
UA_Int64_copy(const UA_Int64 *src, UA_Int64 *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_Int64_deleteMembers(UA_Int64 *p) { }

static UA_INLINE void
UA_Int64_delete(UA_Int64 *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_INT64]);
}

/* UInt64 */
static UA_INLINE void
UA_UInt64_init(UA_UInt64 *p) {
    memset(p, 0, sizeof(UA_UInt64));
}

static UA_INLINE UA_UInt64 *
UA_UInt64_new(void) {
    return (UA_UInt64*)UA_new(&UA_TYPES[UA_TYPES_UINT64]);
}

static UA_INLINE UA_StatusCode
UA_UInt64_copy(const UA_UInt64 *src, UA_UInt64 *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_UInt64_deleteMembers(UA_UInt64 *p) { }

static UA_INLINE void
UA_UInt64_delete(UA_UInt64 *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_UINT64]);
}

/* Float */
static UA_INLINE void
UA_Float_init(UA_Float *p) {
    memset(p, 0, sizeof(UA_Float));
}

static UA_INLINE UA_Float *
UA_Float_new(void) {
    return (UA_Float*)UA_new(&UA_TYPES[UA_TYPES_FLOAT]);
}

static UA_INLINE UA_StatusCode
UA_Float_copy(const UA_Float *src, UA_Float *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_Float_deleteMembers(UA_Float *p) { }

static UA_INLINE void
UA_Float_delete(UA_Float *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_FLOAT]);
}

/* Double */
static UA_INLINE void
UA_Double_init(UA_Double *p) {
    memset(p, 0, sizeof(UA_Double));
}

static UA_INLINE UA_Double *
UA_Double_new(void) {
    return (UA_Double*)UA_new(&UA_TYPES[UA_TYPES_DOUBLE]);
}

static UA_INLINE UA_StatusCode
UA_Double_copy(const UA_Double *src, UA_Double *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_Double_deleteMembers(UA_Double *p) { }

static UA_INLINE void
UA_Double_delete(UA_Double *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DOUBLE]);
}

/* String */
static UA_INLINE void
UA_String_init(UA_String *p) {
    memset(p, 0, sizeof(UA_String));
}

static UA_INLINE UA_String *
UA_String_new(void) {
    return (UA_String*)UA_new(&UA_TYPES[UA_TYPES_STRING]);
}

static UA_INLINE UA_StatusCode
UA_String_copy(const UA_String *src, UA_String *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_STRING]);
}

static UA_INLINE void
UA_String_deleteMembers(UA_String *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_STRING]);
}

static UA_INLINE void
UA_String_delete(UA_String *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_STRING]);
}

/* DateTime */
static UA_INLINE void
UA_DateTime_init(UA_DateTime *p) {
    memset(p, 0, sizeof(UA_DateTime));
}

static UA_INLINE UA_DateTime *
UA_DateTime_new(void) {
    return (UA_DateTime*)UA_new(&UA_TYPES[UA_TYPES_DATETIME]);
}

static UA_INLINE UA_StatusCode
UA_DateTime_copy(const UA_DateTime *src, UA_DateTime *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_DateTime_deleteMembers(UA_DateTime *p) { }

static UA_INLINE void
UA_DateTime_delete(UA_DateTime *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DATETIME]);
}

/* Guid */
static UA_INLINE void
UA_Guid_init(UA_Guid *p) {
    memset(p, 0, sizeof(UA_Guid));
}

static UA_INLINE UA_Guid *
UA_Guid_new(void) {
    return (UA_Guid*)UA_new(&UA_TYPES[UA_TYPES_GUID]);
}

static UA_INLINE UA_StatusCode
UA_Guid_copy(const UA_Guid *src, UA_Guid *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_Guid_deleteMembers(UA_Guid *p) { }

static UA_INLINE void
UA_Guid_delete(UA_Guid *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_GUID]);
}

/* ByteString */
static UA_INLINE void
UA_ByteString_init(UA_ByteString *p) {
    memset(p, 0, sizeof(UA_ByteString));
}

static UA_INLINE UA_ByteString *
UA_ByteString_new(void) {
    return (UA_ByteString*)UA_new(&UA_TYPES[UA_TYPES_BYTESTRING]);
}

static UA_INLINE UA_StatusCode
UA_ByteString_copy(const UA_ByteString *src, UA_ByteString *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

static UA_INLINE void
UA_ByteString_deleteMembers(UA_ByteString *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

static UA_INLINE void
UA_ByteString_delete(UA_ByteString *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BYTESTRING]);
}

/* XmlElement */
static UA_INLINE void
UA_XmlElement_init(UA_XmlElement *p) {
    memset(p, 0, sizeof(UA_XmlElement));
}

static UA_INLINE UA_XmlElement *
UA_XmlElement_new(void) {
    return (UA_XmlElement*)UA_new(&UA_TYPES[UA_TYPES_XMLELEMENT]);
}

static UA_INLINE UA_StatusCode
UA_XmlElement_copy(const UA_XmlElement *src, UA_XmlElement *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_XMLELEMENT]);
}

static UA_INLINE void
UA_XmlElement_deleteMembers(UA_XmlElement *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_XMLELEMENT]);
}

static UA_INLINE void
UA_XmlElement_delete(UA_XmlElement *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_XMLELEMENT]);
}

/* NodeId */
static UA_INLINE void
UA_NodeId_init(UA_NodeId *p) {
    memset(p, 0, sizeof(UA_NodeId));
}

static UA_INLINE UA_NodeId *
UA_NodeId_new(void) {
    return (UA_NodeId*)UA_new(&UA_TYPES[UA_TYPES_NODEID]);
}

static UA_INLINE UA_StatusCode
UA_NodeId_copy(const UA_NodeId *src, UA_NodeId *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_NODEID]);
}

static UA_INLINE void
UA_NodeId_deleteMembers(UA_NodeId *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_NODEID]);
}

static UA_INLINE void
UA_NodeId_delete(UA_NodeId *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_NODEID]);
}

/* ExpandedNodeId */
static UA_INLINE void
UA_ExpandedNodeId_init(UA_ExpandedNodeId *p) {
    memset(p, 0, sizeof(UA_ExpandedNodeId));
}

static UA_INLINE UA_ExpandedNodeId *
UA_ExpandedNodeId_new(void) {
    return (UA_ExpandedNodeId*)UA_new(&UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
}

static UA_INLINE UA_StatusCode
UA_ExpandedNodeId_copy(const UA_ExpandedNodeId *src, UA_ExpandedNodeId *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
}

static UA_INLINE void
UA_ExpandedNodeId_deleteMembers(UA_ExpandedNodeId *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
}

static UA_INLINE void
UA_ExpandedNodeId_delete(UA_ExpandedNodeId *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_EXPANDEDNODEID]);
}

/* StatusCode */
static UA_INLINE void
UA_StatusCode_init(UA_StatusCode *p) {
    memset(p, 0, sizeof(UA_StatusCode));
}

static UA_INLINE UA_StatusCode *
UA_StatusCode_new(void) {
    return (UA_StatusCode*)UA_new(&UA_TYPES[UA_TYPES_STATUSCODE]);
}

static UA_INLINE UA_StatusCode
UA_StatusCode_copy(const UA_StatusCode *src, UA_StatusCode *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_StatusCode_deleteMembers(UA_StatusCode *p) { }

static UA_INLINE void
UA_StatusCode_delete(UA_StatusCode *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_STATUSCODE]);
}

/* QualifiedName */
static UA_INLINE void
UA_QualifiedName_init(UA_QualifiedName *p) {
    memset(p, 0, sizeof(UA_QualifiedName));
}

static UA_INLINE UA_QualifiedName *
UA_QualifiedName_new(void) {
    return (UA_QualifiedName*)UA_new(&UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
}

static UA_INLINE UA_StatusCode
UA_QualifiedName_copy(const UA_QualifiedName *src, UA_QualifiedName *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
}

static UA_INLINE void
UA_QualifiedName_deleteMembers(UA_QualifiedName *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
}

static UA_INLINE void
UA_QualifiedName_delete(UA_QualifiedName *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
}

/* LocalizedText */
static UA_INLINE void
UA_LocalizedText_init(UA_LocalizedText *p) {
    memset(p, 0, sizeof(UA_LocalizedText));
}

static UA_INLINE UA_LocalizedText *
UA_LocalizedText_new(void) {
    return (UA_LocalizedText*)UA_new(&UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE UA_StatusCode
UA_LocalizedText_copy(const UA_LocalizedText *src, UA_LocalizedText *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE void
UA_LocalizedText_deleteMembers(UA_LocalizedText *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE void
UA_LocalizedText_delete(UA_LocalizedText *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

/* ExtensionObject */
static UA_INLINE void
UA_ExtensionObject_init(UA_ExtensionObject *p) {
    memset(p, 0, sizeof(UA_ExtensionObject));
}

static UA_INLINE UA_ExtensionObject *
UA_ExtensionObject_new(void) {
    return (UA_ExtensionObject*)UA_new(&UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
}

static UA_INLINE UA_StatusCode
UA_ExtensionObject_copy(const UA_ExtensionObject *src, UA_ExtensionObject *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
}

static UA_INLINE void
UA_ExtensionObject_deleteMembers(UA_ExtensionObject *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
}

static UA_INLINE void
UA_ExtensionObject_delete(UA_ExtensionObject *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_EXTENSIONOBJECT]);
}

/* DataValue */
static UA_INLINE void
UA_DataValue_init(UA_DataValue *p) {
    memset(p, 0, sizeof(UA_DataValue));
}

static UA_INLINE UA_DataValue *
UA_DataValue_new(void) {
    return (UA_DataValue*)UA_new(&UA_TYPES[UA_TYPES_DATAVALUE]);
}

static UA_INLINE UA_StatusCode
UA_DataValue_copy(const UA_DataValue *src, UA_DataValue *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DATAVALUE]);
}

static UA_INLINE void
UA_DataValue_deleteMembers(UA_DataValue *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DATAVALUE]);
}

static UA_INLINE void
UA_DataValue_delete(UA_DataValue *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DATAVALUE]);
}

/* Variant */
static UA_INLINE void
UA_Variant_init(UA_Variant *p) {
    memset(p, 0, sizeof(UA_Variant));
}

static UA_INLINE UA_Variant *
UA_Variant_new(void) {
    return (UA_Variant*)UA_new(&UA_TYPES[UA_TYPES_VARIANT]);
}

static UA_INLINE UA_StatusCode
UA_Variant_copy(const UA_Variant *src, UA_Variant *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_VARIANT]);
}

static UA_INLINE void
UA_Variant_deleteMembers(UA_Variant *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_VARIANT]);
}

static UA_INLINE void
UA_Variant_delete(UA_Variant *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_VARIANT]);
}

/* DiagnosticInfo */
static UA_INLINE void
UA_DiagnosticInfo_init(UA_DiagnosticInfo *p) {
    memset(p, 0, sizeof(UA_DiagnosticInfo));
}

static UA_INLINE UA_DiagnosticInfo *
UA_DiagnosticInfo_new(void) {
    return (UA_DiagnosticInfo*)UA_new(&UA_TYPES[UA_TYPES_DIAGNOSTICINFO]);
}

static UA_INLINE UA_StatusCode
UA_DiagnosticInfo_copy(const UA_DiagnosticInfo *src, UA_DiagnosticInfo *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DIAGNOSTICINFO]);
}

static UA_INLINE void
UA_DiagnosticInfo_deleteMembers(UA_DiagnosticInfo *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DIAGNOSTICINFO]);
}

static UA_INLINE void
UA_DiagnosticInfo_delete(UA_DiagnosticInfo *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DIAGNOSTICINFO]);
}

/* SignedSoftwareCertificate */
static UA_INLINE void
UA_SignedSoftwareCertificate_init(UA_SignedSoftwareCertificate *p) {
    memset(p, 0, sizeof(UA_SignedSoftwareCertificate));
}

static UA_INLINE UA_SignedSoftwareCertificate *
UA_SignedSoftwareCertificate_new(void) {
    return (UA_SignedSoftwareCertificate*)UA_new(&UA_TYPES[UA_TYPES_SIGNEDSOFTWARECERTIFICATE]);
}

static UA_INLINE UA_StatusCode
UA_SignedSoftwareCertificate_copy(const UA_SignedSoftwareCertificate *src, UA_SignedSoftwareCertificate *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SIGNEDSOFTWARECERTIFICATE]);
}

static UA_INLINE void
UA_SignedSoftwareCertificate_deleteMembers(UA_SignedSoftwareCertificate *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SIGNEDSOFTWARECERTIFICATE]);
}

static UA_INLINE void
UA_SignedSoftwareCertificate_delete(UA_SignedSoftwareCertificate *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SIGNEDSOFTWARECERTIFICATE]);
}

/* SemanticChangeStructureDataType */
static UA_INLINE void
UA_SemanticChangeStructureDataType_init(UA_SemanticChangeStructureDataType *p) {
    memset(p, 0, sizeof(UA_SemanticChangeStructureDataType));
}

static UA_INLINE UA_SemanticChangeStructureDataType *
UA_SemanticChangeStructureDataType_new(void) {
    return (UA_SemanticChangeStructureDataType*)UA_new(&UA_TYPES[UA_TYPES_SEMANTICCHANGESTRUCTUREDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_SemanticChangeStructureDataType_copy(const UA_SemanticChangeStructureDataType *src, UA_SemanticChangeStructureDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SEMANTICCHANGESTRUCTUREDATATYPE]);
}

static UA_INLINE void
UA_SemanticChangeStructureDataType_deleteMembers(UA_SemanticChangeStructureDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SEMANTICCHANGESTRUCTUREDATATYPE]);
}

static UA_INLINE void
UA_SemanticChangeStructureDataType_delete(UA_SemanticChangeStructureDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SEMANTICCHANGESTRUCTUREDATATYPE]);
}

/* StatusChangeNotification */
static UA_INLINE void
UA_StatusChangeNotification_init(UA_StatusChangeNotification *p) {
    memset(p, 0, sizeof(UA_StatusChangeNotification));
}

static UA_INLINE UA_StatusChangeNotification *
UA_StatusChangeNotification_new(void) {
    return (UA_StatusChangeNotification*)UA_new(&UA_TYPES[UA_TYPES_STATUSCHANGENOTIFICATION]);
}

static UA_INLINE UA_StatusCode
UA_StatusChangeNotification_copy(const UA_StatusChangeNotification *src, UA_StatusChangeNotification *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_STATUSCHANGENOTIFICATION]);
}

static UA_INLINE void
UA_StatusChangeNotification_deleteMembers(UA_StatusChangeNotification *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_STATUSCHANGENOTIFICATION]);
}

static UA_INLINE void
UA_StatusChangeNotification_delete(UA_StatusChangeNotification *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_STATUSCHANGENOTIFICATION]);
}

/* BrowsePathTarget */
static UA_INLINE void
UA_BrowsePathTarget_init(UA_BrowsePathTarget *p) {
    memset(p, 0, sizeof(UA_BrowsePathTarget));
}

static UA_INLINE UA_BrowsePathTarget *
UA_BrowsePathTarget_new(void) {
    return (UA_BrowsePathTarget*)UA_new(&UA_TYPES[UA_TYPES_BROWSEPATHTARGET]);
}

static UA_INLINE UA_StatusCode
UA_BrowsePathTarget_copy(const UA_BrowsePathTarget *src, UA_BrowsePathTarget *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSEPATHTARGET]);
}

static UA_INLINE void
UA_BrowsePathTarget_deleteMembers(UA_BrowsePathTarget *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSEPATHTARGET]);
}

static UA_INLINE void
UA_BrowsePathTarget_delete(UA_BrowsePathTarget *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSEPATHTARGET]);
}

/* ViewAttributes */
static UA_INLINE void
UA_ViewAttributes_init(UA_ViewAttributes *p) {
    memset(p, 0, sizeof(UA_ViewAttributes));
}

static UA_INLINE UA_ViewAttributes *
UA_ViewAttributes_new(void) {
    return (UA_ViewAttributes*)UA_new(&UA_TYPES[UA_TYPES_VIEWATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_ViewAttributes_copy(const UA_ViewAttributes *src, UA_ViewAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_VIEWATTRIBUTES]);
}

static UA_INLINE void
UA_ViewAttributes_deleteMembers(UA_ViewAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_VIEWATTRIBUTES]);
}

static UA_INLINE void
UA_ViewAttributes_delete(UA_ViewAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_VIEWATTRIBUTES]);
}

/* RequestHeader */
static UA_INLINE void
UA_RequestHeader_init(UA_RequestHeader *p) {
    memset(p, 0, sizeof(UA_RequestHeader));
}

static UA_INLINE UA_RequestHeader *
UA_RequestHeader_new(void) {
    return (UA_RequestHeader*)UA_new(&UA_TYPES[UA_TYPES_REQUESTHEADER]);
}

static UA_INLINE UA_StatusCode
UA_RequestHeader_copy(const UA_RequestHeader *src, UA_RequestHeader *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REQUESTHEADER]);
}

static UA_INLINE void
UA_RequestHeader_deleteMembers(UA_RequestHeader *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REQUESTHEADER]);
}

static UA_INLINE void
UA_RequestHeader_delete(UA_RequestHeader *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REQUESTHEADER]);
}

/* MonitoredItemModifyResult */
static UA_INLINE void
UA_MonitoredItemModifyResult_init(UA_MonitoredItemModifyResult *p) {
    memset(p, 0, sizeof(UA_MonitoredItemModifyResult));
}

static UA_INLINE UA_MonitoredItemModifyResult *
UA_MonitoredItemModifyResult_new(void) {
    return (UA_MonitoredItemModifyResult*)UA_new(&UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYRESULT]);
}

static UA_INLINE UA_StatusCode
UA_MonitoredItemModifyResult_copy(const UA_MonitoredItemModifyResult *src, UA_MonitoredItemModifyResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYRESULT]);
}

static UA_INLINE void
UA_MonitoredItemModifyResult_deleteMembers(UA_MonitoredItemModifyResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYRESULT]);
}

static UA_INLINE void
UA_MonitoredItemModifyResult_delete(UA_MonitoredItemModifyResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYRESULT]);
}

/* ElementOperand */
static UA_INLINE void
UA_ElementOperand_init(UA_ElementOperand *p) {
    memset(p, 0, sizeof(UA_ElementOperand));
}

static UA_INLINE UA_ElementOperand *
UA_ElementOperand_new(void) {
    return (UA_ElementOperand*)UA_new(&UA_TYPES[UA_TYPES_ELEMENTOPERAND]);
}

static UA_INLINE UA_StatusCode
UA_ElementOperand_copy(const UA_ElementOperand *src, UA_ElementOperand *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_ElementOperand_deleteMembers(UA_ElementOperand *p) { }

static UA_INLINE void
UA_ElementOperand_delete(UA_ElementOperand *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ELEMENTOPERAND]);
}

/* CloseSecureChannelRequest */
static UA_INLINE void
UA_CloseSecureChannelRequest_init(UA_CloseSecureChannelRequest *p) {
    memset(p, 0, sizeof(UA_CloseSecureChannelRequest));
}

static UA_INLINE UA_CloseSecureChannelRequest *
UA_CloseSecureChannelRequest_new(void) {
    return (UA_CloseSecureChannelRequest*)UA_new(&UA_TYPES[UA_TYPES_CLOSESECURECHANNELREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_CloseSecureChannelRequest_copy(const UA_CloseSecureChannelRequest *src, UA_CloseSecureChannelRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CLOSESECURECHANNELREQUEST]);
}

static UA_INLINE void
UA_CloseSecureChannelRequest_deleteMembers(UA_CloseSecureChannelRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CLOSESECURECHANNELREQUEST]);
}

static UA_INLINE void
UA_CloseSecureChannelRequest_delete(UA_CloseSecureChannelRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CLOSESECURECHANNELREQUEST]);
}

/* AddNodesResult */
static UA_INLINE void
UA_AddNodesResult_init(UA_AddNodesResult *p) {
    memset(p, 0, sizeof(UA_AddNodesResult));
}

static UA_INLINE UA_AddNodesResult *
UA_AddNodesResult_new(void) {
    return (UA_AddNodesResult*)UA_new(&UA_TYPES[UA_TYPES_ADDNODESRESULT]);
}

static UA_INLINE UA_StatusCode
UA_AddNodesResult_copy(const UA_AddNodesResult *src, UA_AddNodesResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ADDNODESRESULT]);
}

static UA_INLINE void
UA_AddNodesResult_deleteMembers(UA_AddNodesResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ADDNODESRESULT]);
}

static UA_INLINE void
UA_AddNodesResult_delete(UA_AddNodesResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ADDNODESRESULT]);
}

/* VariableAttributes */
static UA_INLINE void
UA_VariableAttributes_init(UA_VariableAttributes *p) {
    memset(p, 0, sizeof(UA_VariableAttributes));
}

static UA_INLINE UA_VariableAttributes *
UA_VariableAttributes_new(void) {
    return (UA_VariableAttributes*)UA_new(&UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_VariableAttributes_copy(const UA_VariableAttributes *src, UA_VariableAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES]);
}

static UA_INLINE void
UA_VariableAttributes_deleteMembers(UA_VariableAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES]);
}

static UA_INLINE void
UA_VariableAttributes_delete(UA_VariableAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES]);
}

/* NotificationMessage */
static UA_INLINE void
UA_NotificationMessage_init(UA_NotificationMessage *p) {
    memset(p, 0, sizeof(UA_NotificationMessage));
}

static UA_INLINE UA_NotificationMessage *
UA_NotificationMessage_new(void) {
    return (UA_NotificationMessage*)UA_new(&UA_TYPES[UA_TYPES_NOTIFICATIONMESSAGE]);
}

static UA_INLINE UA_StatusCode
UA_NotificationMessage_copy(const UA_NotificationMessage *src, UA_NotificationMessage *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_NOTIFICATIONMESSAGE]);
}

static UA_INLINE void
UA_NotificationMessage_deleteMembers(UA_NotificationMessage *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_NOTIFICATIONMESSAGE]);
}

static UA_INLINE void
UA_NotificationMessage_delete(UA_NotificationMessage *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_NOTIFICATIONMESSAGE]);
}

/* FindServersOnNetworkRequest */
static UA_INLINE void
UA_FindServersOnNetworkRequest_init(UA_FindServersOnNetworkRequest *p) {
    memset(p, 0, sizeof(UA_FindServersOnNetworkRequest));
}

static UA_INLINE UA_FindServersOnNetworkRequest *
UA_FindServersOnNetworkRequest_new(void) {
    return (UA_FindServersOnNetworkRequest*)UA_new(&UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_FindServersOnNetworkRequest_copy(const UA_FindServersOnNetworkRequest *src, UA_FindServersOnNetworkRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKREQUEST]);
}

static UA_INLINE void
UA_FindServersOnNetworkRequest_deleteMembers(UA_FindServersOnNetworkRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKREQUEST]);
}

static UA_INLINE void
UA_FindServersOnNetworkRequest_delete(UA_FindServersOnNetworkRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKREQUEST]);
}

/* EventFieldList */
static UA_INLINE void
UA_EventFieldList_init(UA_EventFieldList *p) {
    memset(p, 0, sizeof(UA_EventFieldList));
}

static UA_INLINE UA_EventFieldList *
UA_EventFieldList_new(void) {
    return (UA_EventFieldList*)UA_new(&UA_TYPES[UA_TYPES_EVENTFIELDLIST]);
}

static UA_INLINE UA_StatusCode
UA_EventFieldList_copy(const UA_EventFieldList *src, UA_EventFieldList *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_EVENTFIELDLIST]);
}

static UA_INLINE void
UA_EventFieldList_deleteMembers(UA_EventFieldList *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_EVENTFIELDLIST]);
}

static UA_INLINE void
UA_EventFieldList_delete(UA_EventFieldList *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_EVENTFIELDLIST]);
}

/* MonitoringMode */
static UA_INLINE void
UA_MonitoringMode_init(UA_MonitoringMode *p) {
    memset(p, 0, sizeof(UA_MonitoringMode));
}

static UA_INLINE UA_MonitoringMode *
UA_MonitoringMode_new(void) {
    return (UA_MonitoringMode*)UA_new(&UA_TYPES[UA_TYPES_MONITORINGMODE]);
}

static UA_INLINE UA_StatusCode
UA_MonitoringMode_copy(const UA_MonitoringMode *src, UA_MonitoringMode *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_MonitoringMode_deleteMembers(UA_MonitoringMode *p) { }

static UA_INLINE void
UA_MonitoringMode_delete(UA_MonitoringMode *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MONITORINGMODE]);
}

/* MdnsDiscoveryConfiguration */
static UA_INLINE void
UA_MdnsDiscoveryConfiguration_init(UA_MdnsDiscoveryConfiguration *p) {
    memset(p, 0, sizeof(UA_MdnsDiscoveryConfiguration));
}

static UA_INLINE UA_MdnsDiscoveryConfiguration *
UA_MdnsDiscoveryConfiguration_new(void) {
    return (UA_MdnsDiscoveryConfiguration*)UA_new(&UA_TYPES[UA_TYPES_MDNSDISCOVERYCONFIGURATION]);
}

static UA_INLINE UA_StatusCode
UA_MdnsDiscoveryConfiguration_copy(const UA_MdnsDiscoveryConfiguration *src, UA_MdnsDiscoveryConfiguration *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MDNSDISCOVERYCONFIGURATION]);
}

static UA_INLINE void
UA_MdnsDiscoveryConfiguration_deleteMembers(UA_MdnsDiscoveryConfiguration *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MDNSDISCOVERYCONFIGURATION]);
}

static UA_INLINE void
UA_MdnsDiscoveryConfiguration_delete(UA_MdnsDiscoveryConfiguration *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MDNSDISCOVERYCONFIGURATION]);
}

/* CallMethodResult */
static UA_INLINE void
UA_CallMethodResult_init(UA_CallMethodResult *p) {
    memset(p, 0, sizeof(UA_CallMethodResult));
}

static UA_INLINE UA_CallMethodResult *
UA_CallMethodResult_new(void) {
    return (UA_CallMethodResult*)UA_new(&UA_TYPES[UA_TYPES_CALLMETHODRESULT]);
}

static UA_INLINE UA_StatusCode
UA_CallMethodResult_copy(const UA_CallMethodResult *src, UA_CallMethodResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CALLMETHODRESULT]);
}

static UA_INLINE void
UA_CallMethodResult_deleteMembers(UA_CallMethodResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CALLMETHODRESULT]);
}

static UA_INLINE void
UA_CallMethodResult_delete(UA_CallMethodResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CALLMETHODRESULT]);
}

/* ParsingResult */
static UA_INLINE void
UA_ParsingResult_init(UA_ParsingResult *p) {
    memset(p, 0, sizeof(UA_ParsingResult));
}

static UA_INLINE UA_ParsingResult *
UA_ParsingResult_new(void) {
    return (UA_ParsingResult*)UA_new(&UA_TYPES[UA_TYPES_PARSINGRESULT]);
}

static UA_INLINE UA_StatusCode
UA_ParsingResult_copy(const UA_ParsingResult *src, UA_ParsingResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_PARSINGRESULT]);
}

static UA_INLINE void
UA_ParsingResult_deleteMembers(UA_ParsingResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_PARSINGRESULT]);
}

static UA_INLINE void
UA_ParsingResult_delete(UA_ParsingResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_PARSINGRESULT]);
}

/* RelativePathElement */
static UA_INLINE void
UA_RelativePathElement_init(UA_RelativePathElement *p) {
    memset(p, 0, sizeof(UA_RelativePathElement));
}

static UA_INLINE UA_RelativePathElement *
UA_RelativePathElement_new(void) {
    return (UA_RelativePathElement*)UA_new(&UA_TYPES[UA_TYPES_RELATIVEPATHELEMENT]);
}

static UA_INLINE UA_StatusCode
UA_RelativePathElement_copy(const UA_RelativePathElement *src, UA_RelativePathElement *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_RELATIVEPATHELEMENT]);
}

static UA_INLINE void
UA_RelativePathElement_deleteMembers(UA_RelativePathElement *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_RELATIVEPATHELEMENT]);
}

static UA_INLINE void
UA_RelativePathElement_delete(UA_RelativePathElement *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_RELATIVEPATHELEMENT]);
}

/* BrowseDirection */
static UA_INLINE void
UA_BrowseDirection_init(UA_BrowseDirection *p) {
    memset(p, 0, sizeof(UA_BrowseDirection));
}

static UA_INLINE UA_BrowseDirection *
UA_BrowseDirection_new(void) {
    return (UA_BrowseDirection*)UA_new(&UA_TYPES[UA_TYPES_BROWSEDIRECTION]);
}

static UA_INLINE UA_StatusCode
UA_BrowseDirection_copy(const UA_BrowseDirection *src, UA_BrowseDirection *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_BrowseDirection_deleteMembers(UA_BrowseDirection *p) { }

static UA_INLINE void
UA_BrowseDirection_delete(UA_BrowseDirection *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSEDIRECTION]);
}

/* CallMethodRequest */
static UA_INLINE void
UA_CallMethodRequest_init(UA_CallMethodRequest *p) {
    memset(p, 0, sizeof(UA_CallMethodRequest));
}

static UA_INLINE UA_CallMethodRequest *
UA_CallMethodRequest_new(void) {
    return (UA_CallMethodRequest*)UA_new(&UA_TYPES[UA_TYPES_CALLMETHODREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_CallMethodRequest_copy(const UA_CallMethodRequest *src, UA_CallMethodRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CALLMETHODREQUEST]);
}

static UA_INLINE void
UA_CallMethodRequest_deleteMembers(UA_CallMethodRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CALLMETHODREQUEST]);
}

static UA_INLINE void
UA_CallMethodRequest_delete(UA_CallMethodRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CALLMETHODREQUEST]);
}

/* RedundancySupport */
static UA_INLINE void
UA_RedundancySupport_init(UA_RedundancySupport *p) {
    memset(p, 0, sizeof(UA_RedundancySupport));
}

static UA_INLINE UA_RedundancySupport *
UA_RedundancySupport_new(void) {
    return (UA_RedundancySupport*)UA_new(&UA_TYPES[UA_TYPES_REDUNDANCYSUPPORT]);
}

static UA_INLINE UA_StatusCode
UA_RedundancySupport_copy(const UA_RedundancySupport *src, UA_RedundancySupport *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_RedundancySupport_deleteMembers(UA_RedundancySupport *p) { }

static UA_INLINE void
UA_RedundancySupport_delete(UA_RedundancySupport *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REDUNDANCYSUPPORT]);
}

/* EventNotificationList */
static UA_INLINE void
UA_EventNotificationList_init(UA_EventNotificationList *p) {
    memset(p, 0, sizeof(UA_EventNotificationList));
}

static UA_INLINE UA_EventNotificationList *
UA_EventNotificationList_new(void) {
    return (UA_EventNotificationList*)UA_new(&UA_TYPES[UA_TYPES_EVENTNOTIFICATIONLIST]);
}

static UA_INLINE UA_StatusCode
UA_EventNotificationList_copy(const UA_EventNotificationList *src, UA_EventNotificationList *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_EVENTNOTIFICATIONLIST]);
}

static UA_INLINE void
UA_EventNotificationList_deleteMembers(UA_EventNotificationList *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_EVENTNOTIFICATIONLIST]);
}

static UA_INLINE void
UA_EventNotificationList_delete(UA_EventNotificationList *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_EVENTNOTIFICATIONLIST]);
}

/* UnregisterNodesRequest */
static UA_INLINE void
UA_UnregisterNodesRequest_init(UA_UnregisterNodesRequest *p) {
    memset(p, 0, sizeof(UA_UnregisterNodesRequest));
}

static UA_INLINE UA_UnregisterNodesRequest *
UA_UnregisterNodesRequest_new(void) {
    return (UA_UnregisterNodesRequest*)UA_new(&UA_TYPES[UA_TYPES_UNREGISTERNODESREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_UnregisterNodesRequest_copy(const UA_UnregisterNodesRequest *src, UA_UnregisterNodesRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_UNREGISTERNODESREQUEST]);
}

static UA_INLINE void
UA_UnregisterNodesRequest_deleteMembers(UA_UnregisterNodesRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_UNREGISTERNODESREQUEST]);
}

static UA_INLINE void
UA_UnregisterNodesRequest_delete(UA_UnregisterNodesRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_UNREGISTERNODESREQUEST]);
}

/* ContentFilterElementResult */
static UA_INLINE void
UA_ContentFilterElementResult_init(UA_ContentFilterElementResult *p) {
    memset(p, 0, sizeof(UA_ContentFilterElementResult));
}

static UA_INLINE UA_ContentFilterElementResult *
UA_ContentFilterElementResult_new(void) {
    return (UA_ContentFilterElementResult*)UA_new(&UA_TYPES[UA_TYPES_CONTENTFILTERELEMENTRESULT]);
}

static UA_INLINE UA_StatusCode
UA_ContentFilterElementResult_copy(const UA_ContentFilterElementResult *src, UA_ContentFilterElementResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENTRESULT]);
}

static UA_INLINE void
UA_ContentFilterElementResult_deleteMembers(UA_ContentFilterElementResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENTRESULT]);
}

static UA_INLINE void
UA_ContentFilterElementResult_delete(UA_ContentFilterElementResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENTRESULT]);
}

/* SimpleAttributeOperand */
static UA_INLINE void
UA_SimpleAttributeOperand_init(UA_SimpleAttributeOperand *p) {
    memset(p, 0, sizeof(UA_SimpleAttributeOperand));
}

static UA_INLINE UA_SimpleAttributeOperand *
UA_SimpleAttributeOperand_new(void) {
    return (UA_SimpleAttributeOperand*)UA_new(&UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
}

static UA_INLINE UA_StatusCode
UA_SimpleAttributeOperand_copy(const UA_SimpleAttributeOperand *src, UA_SimpleAttributeOperand *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
}

static UA_INLINE void
UA_SimpleAttributeOperand_deleteMembers(UA_SimpleAttributeOperand *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
}

static UA_INLINE void
UA_SimpleAttributeOperand_delete(UA_SimpleAttributeOperand *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SIMPLEATTRIBUTEOPERAND]);
}

/* LiteralOperand */
static UA_INLINE void
UA_LiteralOperand_init(UA_LiteralOperand *p) {
    memset(p, 0, sizeof(UA_LiteralOperand));
}

static UA_INLINE UA_LiteralOperand *
UA_LiteralOperand_new(void) {
    return (UA_LiteralOperand*)UA_new(&UA_TYPES[UA_TYPES_LITERALOPERAND]);
}

static UA_INLINE UA_StatusCode
UA_LiteralOperand_copy(const UA_LiteralOperand *src, UA_LiteralOperand *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
}

static UA_INLINE void
UA_LiteralOperand_deleteMembers(UA_LiteralOperand *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
}

static UA_INLINE void
UA_LiteralOperand_delete(UA_LiteralOperand *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_LITERALOPERAND]);
}

/* QueryDataSet */
static UA_INLINE void
UA_QueryDataSet_init(UA_QueryDataSet *p) {
    memset(p, 0, sizeof(UA_QueryDataSet));
}

static UA_INLINE UA_QueryDataSet *
UA_QueryDataSet_new(void) {
    return (UA_QueryDataSet*)UA_new(&UA_TYPES[UA_TYPES_QUERYDATASET]);
}

static UA_INLINE UA_StatusCode
UA_QueryDataSet_copy(const UA_QueryDataSet *src, UA_QueryDataSet *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_QUERYDATASET]);
}

static UA_INLINE void
UA_QueryDataSet_deleteMembers(UA_QueryDataSet *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_QUERYDATASET]);
}

static UA_INLINE void
UA_QueryDataSet_delete(UA_QueryDataSet *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_QUERYDATASET]);
}

/* AnonymousIdentityToken */
static UA_INLINE void
UA_AnonymousIdentityToken_init(UA_AnonymousIdentityToken *p) {
    memset(p, 0, sizeof(UA_AnonymousIdentityToken));
}

static UA_INLINE UA_AnonymousIdentityToken *
UA_AnonymousIdentityToken_new(void) {
    return (UA_AnonymousIdentityToken*)UA_new(&UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]);
}

static UA_INLINE UA_StatusCode
UA_AnonymousIdentityToken_copy(const UA_AnonymousIdentityToken *src, UA_AnonymousIdentityToken *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]);
}

static UA_INLINE void
UA_AnonymousIdentityToken_deleteMembers(UA_AnonymousIdentityToken *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]);
}

static UA_INLINE void
UA_AnonymousIdentityToken_delete(UA_AnonymousIdentityToken *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN]);
}

/* SetPublishingModeRequest */
static UA_INLINE void
UA_SetPublishingModeRequest_init(UA_SetPublishingModeRequest *p) {
    memset(p, 0, sizeof(UA_SetPublishingModeRequest));
}

static UA_INLINE UA_SetPublishingModeRequest *
UA_SetPublishingModeRequest_new(void) {
    return (UA_SetPublishingModeRequest*)UA_new(&UA_TYPES[UA_TYPES_SETPUBLISHINGMODEREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_SetPublishingModeRequest_copy(const UA_SetPublishingModeRequest *src, UA_SetPublishingModeRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SETPUBLISHINGMODEREQUEST]);
}

static UA_INLINE void
UA_SetPublishingModeRequest_deleteMembers(UA_SetPublishingModeRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SETPUBLISHINGMODEREQUEST]);
}

static UA_INLINE void
UA_SetPublishingModeRequest_delete(UA_SetPublishingModeRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SETPUBLISHINGMODEREQUEST]);
}

/* MonitoredItemCreateResult */
static UA_INLINE void
UA_MonitoredItemCreateResult_init(UA_MonitoredItemCreateResult *p) {
    memset(p, 0, sizeof(UA_MonitoredItemCreateResult));
}

static UA_INLINE UA_MonitoredItemCreateResult *
UA_MonitoredItemCreateResult_new(void) {
    return (UA_MonitoredItemCreateResult*)UA_new(&UA_TYPES[UA_TYPES_MONITOREDITEMCREATERESULT]);
}

static UA_INLINE UA_StatusCode
UA_MonitoredItemCreateResult_copy(const UA_MonitoredItemCreateResult *src, UA_MonitoredItemCreateResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MONITOREDITEMCREATERESULT]);
}

static UA_INLINE void
UA_MonitoredItemCreateResult_deleteMembers(UA_MonitoredItemCreateResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MONITOREDITEMCREATERESULT]);
}

static UA_INLINE void
UA_MonitoredItemCreateResult_delete(UA_MonitoredItemCreateResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MONITOREDITEMCREATERESULT]);
}

/* TimestampsToReturn */
static UA_INLINE void
UA_TimestampsToReturn_init(UA_TimestampsToReturn *p) {
    memset(p, 0, sizeof(UA_TimestampsToReturn));
}

static UA_INLINE UA_TimestampsToReturn *
UA_TimestampsToReturn_new(void) {
    return (UA_TimestampsToReturn*)UA_new(&UA_TYPES[UA_TYPES_TIMESTAMPSTORETURN]);
}

static UA_INLINE UA_StatusCode
UA_TimestampsToReturn_copy(const UA_TimestampsToReturn *src, UA_TimestampsToReturn *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_TimestampsToReturn_deleteMembers(UA_TimestampsToReturn *p) { }

static UA_INLINE void
UA_TimestampsToReturn_delete(UA_TimestampsToReturn *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_TIMESTAMPSTORETURN]);
}

/* CallRequest */
static UA_INLINE void
UA_CallRequest_init(UA_CallRequest *p) {
    memset(p, 0, sizeof(UA_CallRequest));
}

static UA_INLINE UA_CallRequest *
UA_CallRequest_new(void) {
    return (UA_CallRequest*)UA_new(&UA_TYPES[UA_TYPES_CALLREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_CallRequest_copy(const UA_CallRequest *src, UA_CallRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CALLREQUEST]);
}

static UA_INLINE void
UA_CallRequest_deleteMembers(UA_CallRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CALLREQUEST]);
}

static UA_INLINE void
UA_CallRequest_delete(UA_CallRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CALLREQUEST]);
}

/* MethodAttributes */
static UA_INLINE void
UA_MethodAttributes_init(UA_MethodAttributes *p) {
    memset(p, 0, sizeof(UA_MethodAttributes));
}

static UA_INLINE UA_MethodAttributes *
UA_MethodAttributes_new(void) {
    return (UA_MethodAttributes*)UA_new(&UA_TYPES[UA_TYPES_METHODATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_MethodAttributes_copy(const UA_MethodAttributes *src, UA_MethodAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_METHODATTRIBUTES]);
}

static UA_INLINE void
UA_MethodAttributes_deleteMembers(UA_MethodAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_METHODATTRIBUTES]);
}

static UA_INLINE void
UA_MethodAttributes_delete(UA_MethodAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_METHODATTRIBUTES]);
}

/* DeleteReferencesItem */
static UA_INLINE void
UA_DeleteReferencesItem_init(UA_DeleteReferencesItem *p) {
    memset(p, 0, sizeof(UA_DeleteReferencesItem));
}

static UA_INLINE UA_DeleteReferencesItem *
UA_DeleteReferencesItem_new(void) {
    return (UA_DeleteReferencesItem*)UA_new(&UA_TYPES[UA_TYPES_DELETEREFERENCESITEM]);
}

static UA_INLINE UA_StatusCode
UA_DeleteReferencesItem_copy(const UA_DeleteReferencesItem *src, UA_DeleteReferencesItem *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETEREFERENCESITEM]);
}

static UA_INLINE void
UA_DeleteReferencesItem_deleteMembers(UA_DeleteReferencesItem *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETEREFERENCESITEM]);
}

static UA_INLINE void
UA_DeleteReferencesItem_delete(UA_DeleteReferencesItem *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETEREFERENCESITEM]);
}

/* WriteValue */
static UA_INLINE void
UA_WriteValue_init(UA_WriteValue *p) {
    memset(p, 0, sizeof(UA_WriteValue));
}

static UA_INLINE UA_WriteValue *
UA_WriteValue_new(void) {
    return (UA_WriteValue*)UA_new(&UA_TYPES[UA_TYPES_WRITEVALUE]);
}

static UA_INLINE UA_StatusCode
UA_WriteValue_copy(const UA_WriteValue *src, UA_WriteValue *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_WRITEVALUE]);
}

static UA_INLINE void
UA_WriteValue_deleteMembers(UA_WriteValue *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_WRITEVALUE]);
}

static UA_INLINE void
UA_WriteValue_delete(UA_WriteValue *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_WRITEVALUE]);
}

/* NodeAttributesMask */
static UA_INLINE void
UA_NodeAttributesMask_init(UA_NodeAttributesMask *p) {
    memset(p, 0, sizeof(UA_NodeAttributesMask));
}

static UA_INLINE UA_NodeAttributesMask *
UA_NodeAttributesMask_new(void) {
    return (UA_NodeAttributesMask*)UA_new(&UA_TYPES[UA_TYPES_NODEATTRIBUTESMASK]);
}

static UA_INLINE UA_StatusCode
UA_NodeAttributesMask_copy(const UA_NodeAttributesMask *src, UA_NodeAttributesMask *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_NodeAttributesMask_deleteMembers(UA_NodeAttributesMask *p) { }

static UA_INLINE void
UA_NodeAttributesMask_delete(UA_NodeAttributesMask *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_NODEATTRIBUTESMASK]);
}

/* MessageSecurityMode */
static UA_INLINE void
UA_MessageSecurityMode_init(UA_MessageSecurityMode *p) {
    memset(p, 0, sizeof(UA_MessageSecurityMode));
}

static UA_INLINE UA_MessageSecurityMode *
UA_MessageSecurityMode_new(void) {
    return (UA_MessageSecurityMode*)UA_new(&UA_TYPES[UA_TYPES_MESSAGESECURITYMODE]);
}

static UA_INLINE UA_StatusCode
UA_MessageSecurityMode_copy(const UA_MessageSecurityMode *src, UA_MessageSecurityMode *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_MessageSecurityMode_deleteMembers(UA_MessageSecurityMode *p) { }

static UA_INLINE void
UA_MessageSecurityMode_delete(UA_MessageSecurityMode *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MESSAGESECURITYMODE]);
}

/* MonitoringParameters */
static UA_INLINE void
UA_MonitoringParameters_init(UA_MonitoringParameters *p) {
    memset(p, 0, sizeof(UA_MonitoringParameters));
}

static UA_INLINE UA_MonitoringParameters *
UA_MonitoringParameters_new(void) {
    return (UA_MonitoringParameters*)UA_new(&UA_TYPES[UA_TYPES_MONITORINGPARAMETERS]);
}

static UA_INLINE UA_StatusCode
UA_MonitoringParameters_copy(const UA_MonitoringParameters *src, UA_MonitoringParameters *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MONITORINGPARAMETERS]);
}

static UA_INLINE void
UA_MonitoringParameters_deleteMembers(UA_MonitoringParameters *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MONITORINGPARAMETERS]);
}

static UA_INLINE void
UA_MonitoringParameters_delete(UA_MonitoringParameters *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MONITORINGPARAMETERS]);
}

/* ReferenceNode */
static UA_INLINE void
UA_ReferenceNode_init(UA_ReferenceNode *p) {
    memset(p, 0, sizeof(UA_ReferenceNode));
}

static UA_INLINE UA_ReferenceNode *
UA_ReferenceNode_new(void) {
    return (UA_ReferenceNode*)UA_new(&UA_TYPES[UA_TYPES_REFERENCENODE]);
}

static UA_INLINE UA_StatusCode
UA_ReferenceNode_copy(const UA_ReferenceNode *src, UA_ReferenceNode *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REFERENCENODE]);
}

static UA_INLINE void
UA_ReferenceNode_deleteMembers(UA_ReferenceNode *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REFERENCENODE]);
}

static UA_INLINE void
UA_ReferenceNode_delete(UA_ReferenceNode *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REFERENCENODE]);
}

/* Argument */
static UA_INLINE void
UA_Argument_init(UA_Argument *p) {
    memset(p, 0, sizeof(UA_Argument));
}

static UA_INLINE UA_Argument *
UA_Argument_new(void) {
    return (UA_Argument*)UA_new(&UA_TYPES[UA_TYPES_ARGUMENT]);
}

static UA_INLINE UA_StatusCode
UA_Argument_copy(const UA_Argument *src, UA_Argument *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ARGUMENT]);
}

static UA_INLINE void
UA_Argument_deleteMembers(UA_Argument *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ARGUMENT]);
}

static UA_INLINE void
UA_Argument_delete(UA_Argument *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ARGUMENT]);
}

/* ChannelSecurityToken */
static UA_INLINE void
UA_ChannelSecurityToken_init(UA_ChannelSecurityToken *p) {
    memset(p, 0, sizeof(UA_ChannelSecurityToken));
}

static UA_INLINE UA_ChannelSecurityToken *
UA_ChannelSecurityToken_new(void) {
    return (UA_ChannelSecurityToken*)UA_new(&UA_TYPES[UA_TYPES_CHANNELSECURITYTOKEN]);
}

static UA_INLINE UA_StatusCode
UA_ChannelSecurityToken_copy(const UA_ChannelSecurityToken *src, UA_ChannelSecurityToken *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_ChannelSecurityToken_deleteMembers(UA_ChannelSecurityToken *p) { }

static UA_INLINE void
UA_ChannelSecurityToken_delete(UA_ChannelSecurityToken *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CHANNELSECURITYTOKEN]);
}

/* UserIdentityToken */
static UA_INLINE void
UA_UserIdentityToken_init(UA_UserIdentityToken *p) {
    memset(p, 0, sizeof(UA_UserIdentityToken));
}

static UA_INLINE UA_UserIdentityToken *
UA_UserIdentityToken_new(void) {
    return (UA_UserIdentityToken*)UA_new(&UA_TYPES[UA_TYPES_USERIDENTITYTOKEN]);
}

static UA_INLINE UA_StatusCode
UA_UserIdentityToken_copy(const UA_UserIdentityToken *src, UA_UserIdentityToken *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_USERIDENTITYTOKEN]);
}

static UA_INLINE void
UA_UserIdentityToken_deleteMembers(UA_UserIdentityToken *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_USERIDENTITYTOKEN]);
}

static UA_INLINE void
UA_UserIdentityToken_delete(UA_UserIdentityToken *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_USERIDENTITYTOKEN]);
}

/* SignatureData */
static UA_INLINE void
UA_SignatureData_init(UA_SignatureData *p) {
    memset(p, 0, sizeof(UA_SignatureData));
}

static UA_INLINE UA_SignatureData *
UA_SignatureData_new(void) {
    return (UA_SignatureData*)UA_new(&UA_TYPES[UA_TYPES_SIGNATUREDATA]);
}

static UA_INLINE UA_StatusCode
UA_SignatureData_copy(const UA_SignatureData *src, UA_SignatureData *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SIGNATUREDATA]);
}

static UA_INLINE void
UA_SignatureData_deleteMembers(UA_SignatureData *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SIGNATUREDATA]);
}

static UA_INLINE void
UA_SignatureData_delete(UA_SignatureData *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SIGNATUREDATA]);
}

/* ObjectTypeAttributes */
static UA_INLINE void
UA_ObjectTypeAttributes_init(UA_ObjectTypeAttributes *p) {
    memset(p, 0, sizeof(UA_ObjectTypeAttributes));
}

static UA_INLINE UA_ObjectTypeAttributes *
UA_ObjectTypeAttributes_new(void) {
    return (UA_ObjectTypeAttributes*)UA_new(&UA_TYPES[UA_TYPES_OBJECTTYPEATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_ObjectTypeAttributes_copy(const UA_ObjectTypeAttributes *src, UA_ObjectTypeAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_OBJECTTYPEATTRIBUTES]);
}

static UA_INLINE void
UA_ObjectTypeAttributes_deleteMembers(UA_ObjectTypeAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_OBJECTTYPEATTRIBUTES]);
}

static UA_INLINE void
UA_ObjectTypeAttributes_delete(UA_ObjectTypeAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_OBJECTTYPEATTRIBUTES]);
}

/* DeadbandType */
static UA_INLINE void
UA_DeadbandType_init(UA_DeadbandType *p) {
    memset(p, 0, sizeof(UA_DeadbandType));
}

static UA_INLINE UA_DeadbandType *
UA_DeadbandType_new(void) {
    return (UA_DeadbandType*)UA_new(&UA_TYPES[UA_TYPES_DEADBANDTYPE]);
}

static UA_INLINE UA_StatusCode
UA_DeadbandType_copy(const UA_DeadbandType *src, UA_DeadbandType *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_DeadbandType_deleteMembers(UA_DeadbandType *p) { }

static UA_INLINE void
UA_DeadbandType_delete(UA_DeadbandType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DEADBANDTYPE]);
}

/* SecurityTokenRequestType */
static UA_INLINE void
UA_SecurityTokenRequestType_init(UA_SecurityTokenRequestType *p) {
    memset(p, 0, sizeof(UA_SecurityTokenRequestType));
}

static UA_INLINE UA_SecurityTokenRequestType *
UA_SecurityTokenRequestType_new(void) {
    return (UA_SecurityTokenRequestType*)UA_new(&UA_TYPES[UA_TYPES_SECURITYTOKENREQUESTTYPE]);
}

static UA_INLINE UA_StatusCode
UA_SecurityTokenRequestType_copy(const UA_SecurityTokenRequestType *src, UA_SecurityTokenRequestType *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_SecurityTokenRequestType_deleteMembers(UA_SecurityTokenRequestType *p) { }

static UA_INLINE void
UA_SecurityTokenRequestType_delete(UA_SecurityTokenRequestType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SECURITYTOKENREQUESTTYPE]);
}

/* NodeAttributes */
static UA_INLINE void
UA_NodeAttributes_init(UA_NodeAttributes *p) {
    memset(p, 0, sizeof(UA_NodeAttributes));
}

static UA_INLINE UA_NodeAttributes *
UA_NodeAttributes_new(void) {
    return (UA_NodeAttributes*)UA_new(&UA_TYPES[UA_TYPES_NODEATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_NodeAttributes_copy(const UA_NodeAttributes *src, UA_NodeAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_NODEATTRIBUTES]);
}

static UA_INLINE void
UA_NodeAttributes_deleteMembers(UA_NodeAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_NODEATTRIBUTES]);
}

static UA_INLINE void
UA_NodeAttributes_delete(UA_NodeAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_NODEATTRIBUTES]);
}

/* DataChangeTrigger */
static UA_INLINE void
UA_DataChangeTrigger_init(UA_DataChangeTrigger *p) {
    memset(p, 0, sizeof(UA_DataChangeTrigger));
}

static UA_INLINE UA_DataChangeTrigger *
UA_DataChangeTrigger_new(void) {
    return (UA_DataChangeTrigger*)UA_new(&UA_TYPES[UA_TYPES_DATACHANGETRIGGER]);
}

static UA_INLINE UA_StatusCode
UA_DataChangeTrigger_copy(const UA_DataChangeTrigger *src, UA_DataChangeTrigger *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_DataChangeTrigger_deleteMembers(UA_DataChangeTrigger *p) { }

static UA_INLINE void
UA_DataChangeTrigger_delete(UA_DataChangeTrigger *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DATACHANGETRIGGER]);
}

/* BuildInfo */
static UA_INLINE void
UA_BuildInfo_init(UA_BuildInfo *p) {
    memset(p, 0, sizeof(UA_BuildInfo));
}

static UA_INLINE UA_BuildInfo *
UA_BuildInfo_new(void) {
    return (UA_BuildInfo*)UA_new(&UA_TYPES[UA_TYPES_BUILDINFO]);
}

static UA_INLINE UA_StatusCode
UA_BuildInfo_copy(const UA_BuildInfo *src, UA_BuildInfo *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BUILDINFO]);
}

static UA_INLINE void
UA_BuildInfo_deleteMembers(UA_BuildInfo *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BUILDINFO]);
}

static UA_INLINE void
UA_BuildInfo_delete(UA_BuildInfo *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BUILDINFO]);
}

/* NodeClass */
static UA_INLINE void
UA_NodeClass_init(UA_NodeClass *p) {
    memset(p, 0, sizeof(UA_NodeClass));
}

static UA_INLINE UA_NodeClass *
UA_NodeClass_new(void) {
    return (UA_NodeClass*)UA_new(&UA_TYPES[UA_TYPES_NODECLASS]);
}

static UA_INLINE UA_StatusCode
UA_NodeClass_copy(const UA_NodeClass *src, UA_NodeClass *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_NodeClass_deleteMembers(UA_NodeClass *p) { }

static UA_INLINE void
UA_NodeClass_delete(UA_NodeClass *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_NODECLASS]);
}

/* SubscriptionDiagnosticsDataType */
static UA_INLINE void
UA_SubscriptionDiagnosticsDataType_init(UA_SubscriptionDiagnosticsDataType *p) {
    memset(p, 0, sizeof(UA_SubscriptionDiagnosticsDataType));
}

static UA_INLINE UA_SubscriptionDiagnosticsDataType *
UA_SubscriptionDiagnosticsDataType_new(void) {
    return (UA_SubscriptionDiagnosticsDataType*)UA_new(&UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_SubscriptionDiagnosticsDataType_copy(const UA_SubscriptionDiagnosticsDataType *src, UA_SubscriptionDiagnosticsDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]);
}

static UA_INLINE void
UA_SubscriptionDiagnosticsDataType_deleteMembers(UA_SubscriptionDiagnosticsDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]);
}

static UA_INLINE void
UA_SubscriptionDiagnosticsDataType_delete(UA_SubscriptionDiagnosticsDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SUBSCRIPTIONDIAGNOSTICSDATATYPE]);
}

/* FilterOperand */
static UA_INLINE void
UA_FilterOperand_init(UA_FilterOperand *p) {
    memset(p, 0, sizeof(UA_FilterOperand));
}

static UA_INLINE UA_FilterOperand *
UA_FilterOperand_new(void) {
    return (UA_FilterOperand*)UA_new(&UA_TYPES[UA_TYPES_FILTEROPERAND]);
}

static UA_INLINE UA_StatusCode
UA_FilterOperand_copy(const UA_FilterOperand *src, UA_FilterOperand *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_FilterOperand_deleteMembers(UA_FilterOperand *p) { }

static UA_INLINE void
UA_FilterOperand_delete(UA_FilterOperand *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_FILTEROPERAND]);
}

/* MonitoredItemNotification */
static UA_INLINE void
UA_MonitoredItemNotification_init(UA_MonitoredItemNotification *p) {
    memset(p, 0, sizeof(UA_MonitoredItemNotification));
}

static UA_INLINE UA_MonitoredItemNotification *
UA_MonitoredItemNotification_new(void) {
    return (UA_MonitoredItemNotification*)UA_new(&UA_TYPES[UA_TYPES_MONITOREDITEMNOTIFICATION]);
}

static UA_INLINE UA_StatusCode
UA_MonitoredItemNotification_copy(const UA_MonitoredItemNotification *src, UA_MonitoredItemNotification *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MONITOREDITEMNOTIFICATION]);
}

static UA_INLINE void
UA_MonitoredItemNotification_deleteMembers(UA_MonitoredItemNotification *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MONITOREDITEMNOTIFICATION]);
}

static UA_INLINE void
UA_MonitoredItemNotification_delete(UA_MonitoredItemNotification *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MONITOREDITEMNOTIFICATION]);
}

/* DeleteNodesItem */
static UA_INLINE void
UA_DeleteNodesItem_init(UA_DeleteNodesItem *p) {
    memset(p, 0, sizeof(UA_DeleteNodesItem));
}

static UA_INLINE UA_DeleteNodesItem *
UA_DeleteNodesItem_new(void) {
    return (UA_DeleteNodesItem*)UA_new(&UA_TYPES[UA_TYPES_DELETENODESITEM]);
}

static UA_INLINE UA_StatusCode
UA_DeleteNodesItem_copy(const UA_DeleteNodesItem *src, UA_DeleteNodesItem *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETENODESITEM]);
}

static UA_INLINE void
UA_DeleteNodesItem_deleteMembers(UA_DeleteNodesItem *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETENODESITEM]);
}

static UA_INLINE void
UA_DeleteNodesItem_delete(UA_DeleteNodesItem *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETENODESITEM]);
}

/* DeleteSubscriptionsRequest */
static UA_INLINE void
UA_DeleteSubscriptionsRequest_init(UA_DeleteSubscriptionsRequest *p) {
    memset(p, 0, sizeof(UA_DeleteSubscriptionsRequest));
}

static UA_INLINE UA_DeleteSubscriptionsRequest *
UA_DeleteSubscriptionsRequest_new(void) {
    return (UA_DeleteSubscriptionsRequest*)UA_new(&UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_DeleteSubscriptionsRequest_copy(const UA_DeleteSubscriptionsRequest *src, UA_DeleteSubscriptionsRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSREQUEST]);
}

static UA_INLINE void
UA_DeleteSubscriptionsRequest_deleteMembers(UA_DeleteSubscriptionsRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSREQUEST]);
}

static UA_INLINE void
UA_DeleteSubscriptionsRequest_delete(UA_DeleteSubscriptionsRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSREQUEST]);
}

/* SubscriptionAcknowledgement */
static UA_INLINE void
UA_SubscriptionAcknowledgement_init(UA_SubscriptionAcknowledgement *p) {
    memset(p, 0, sizeof(UA_SubscriptionAcknowledgement));
}

static UA_INLINE UA_SubscriptionAcknowledgement *
UA_SubscriptionAcknowledgement_new(void) {
    return (UA_SubscriptionAcknowledgement*)UA_new(&UA_TYPES[UA_TYPES_SUBSCRIPTIONACKNOWLEDGEMENT]);
}

static UA_INLINE UA_StatusCode
UA_SubscriptionAcknowledgement_copy(const UA_SubscriptionAcknowledgement *src, UA_SubscriptionAcknowledgement *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_SubscriptionAcknowledgement_deleteMembers(UA_SubscriptionAcknowledgement *p) { }

static UA_INLINE void
UA_SubscriptionAcknowledgement_delete(UA_SubscriptionAcknowledgement *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SUBSCRIPTIONACKNOWLEDGEMENT]);
}

/* ReadValueId */
static UA_INLINE void
UA_ReadValueId_init(UA_ReadValueId *p) {
    memset(p, 0, sizeof(UA_ReadValueId));
}

static UA_INLINE UA_ReadValueId *
UA_ReadValueId_new(void) {
    return (UA_ReadValueId*)UA_new(&UA_TYPES[UA_TYPES_READVALUEID]);
}

static UA_INLINE UA_StatusCode
UA_ReadValueId_copy(const UA_ReadValueId *src, UA_ReadValueId *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_READVALUEID]);
}

static UA_INLINE void
UA_ReadValueId_deleteMembers(UA_ReadValueId *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_READVALUEID]);
}

static UA_INLINE void
UA_ReadValueId_delete(UA_ReadValueId *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_READVALUEID]);
}

/* DataTypeAttributes */
static UA_INLINE void
UA_DataTypeAttributes_init(UA_DataTypeAttributes *p) {
    memset(p, 0, sizeof(UA_DataTypeAttributes));
}

static UA_INLINE UA_DataTypeAttributes *
UA_DataTypeAttributes_new(void) {
    return (UA_DataTypeAttributes*)UA_new(&UA_TYPES[UA_TYPES_DATATYPEATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_DataTypeAttributes_copy(const UA_DataTypeAttributes *src, UA_DataTypeAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DATATYPEATTRIBUTES]);
}

static UA_INLINE void
UA_DataTypeAttributes_deleteMembers(UA_DataTypeAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DATATYPEATTRIBUTES]);
}

static UA_INLINE void
UA_DataTypeAttributes_delete(UA_DataTypeAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DATATYPEATTRIBUTES]);
}

/* ResponseHeader */
static UA_INLINE void
UA_ResponseHeader_init(UA_ResponseHeader *p) {
    memset(p, 0, sizeof(UA_ResponseHeader));
}

static UA_INLINE UA_ResponseHeader *
UA_ResponseHeader_new(void) {
    return (UA_ResponseHeader*)UA_new(&UA_TYPES[UA_TYPES_RESPONSEHEADER]);
}

static UA_INLINE UA_StatusCode
UA_ResponseHeader_copy(const UA_ResponseHeader *src, UA_ResponseHeader *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_RESPONSEHEADER]);
}

static UA_INLINE void
UA_ResponseHeader_deleteMembers(UA_ResponseHeader *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_RESPONSEHEADER]);
}

static UA_INLINE void
UA_ResponseHeader_delete(UA_ResponseHeader *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_RESPONSEHEADER]);
}

/* DeleteMonitoredItemsRequest */
static UA_INLINE void
UA_DeleteMonitoredItemsRequest_init(UA_DeleteMonitoredItemsRequest *p) {
    memset(p, 0, sizeof(UA_DeleteMonitoredItemsRequest));
}

static UA_INLINE UA_DeleteMonitoredItemsRequest *
UA_DeleteMonitoredItemsRequest_new(void) {
    return (UA_DeleteMonitoredItemsRequest*)UA_new(&UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_DeleteMonitoredItemsRequest_copy(const UA_DeleteMonitoredItemsRequest *src, UA_DeleteMonitoredItemsRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSREQUEST]);
}

static UA_INLINE void
UA_DeleteMonitoredItemsRequest_deleteMembers(UA_DeleteMonitoredItemsRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSREQUEST]);
}

static UA_INLINE void
UA_DeleteMonitoredItemsRequest_delete(UA_DeleteMonitoredItemsRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSREQUEST]);
}

/* ViewDescription */
static UA_INLINE void
UA_ViewDescription_init(UA_ViewDescription *p) {
    memset(p, 0, sizeof(UA_ViewDescription));
}

static UA_INLINE UA_ViewDescription *
UA_ViewDescription_new(void) {
    return (UA_ViewDescription*)UA_new(&UA_TYPES[UA_TYPES_VIEWDESCRIPTION]);
}

static UA_INLINE UA_StatusCode
UA_ViewDescription_copy(const UA_ViewDescription *src, UA_ViewDescription *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_VIEWDESCRIPTION]);
}

static UA_INLINE void
UA_ViewDescription_deleteMembers(UA_ViewDescription *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_VIEWDESCRIPTION]);
}

static UA_INLINE void
UA_ViewDescription_delete(UA_ViewDescription *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_VIEWDESCRIPTION]);
}

/* ServerOnNetwork */
static UA_INLINE void
UA_ServerOnNetwork_init(UA_ServerOnNetwork *p) {
    memset(p, 0, sizeof(UA_ServerOnNetwork));
}

static UA_INLINE UA_ServerOnNetwork *
UA_ServerOnNetwork_new(void) {
    return (UA_ServerOnNetwork*)UA_new(&UA_TYPES[UA_TYPES_SERVERONNETWORK]);
}

static UA_INLINE UA_StatusCode
UA_ServerOnNetwork_copy(const UA_ServerOnNetwork *src, UA_ServerOnNetwork *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SERVERONNETWORK]);
}

static UA_INLINE void
UA_ServerOnNetwork_deleteMembers(UA_ServerOnNetwork *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SERVERONNETWORK]);
}

static UA_INLINE void
UA_ServerOnNetwork_delete(UA_ServerOnNetwork *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SERVERONNETWORK]);
}

/* DeleteMonitoredItemsResponse */
static UA_INLINE void
UA_DeleteMonitoredItemsResponse_init(UA_DeleteMonitoredItemsResponse *p) {
    memset(p, 0, sizeof(UA_DeleteMonitoredItemsResponse));
}

static UA_INLINE UA_DeleteMonitoredItemsResponse *
UA_DeleteMonitoredItemsResponse_new(void) {
    return (UA_DeleteMonitoredItemsResponse*)UA_new(&UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_DeleteMonitoredItemsResponse_copy(const UA_DeleteMonitoredItemsResponse *src, UA_DeleteMonitoredItemsResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSRESPONSE]);
}

static UA_INLINE void
UA_DeleteMonitoredItemsResponse_deleteMembers(UA_DeleteMonitoredItemsResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSRESPONSE]);
}

static UA_INLINE void
UA_DeleteMonitoredItemsResponse_delete(UA_DeleteMonitoredItemsResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETEMONITOREDITEMSRESPONSE]);
}

/* FindServersOnNetworkResponse */
static UA_INLINE void
UA_FindServersOnNetworkResponse_init(UA_FindServersOnNetworkResponse *p) {
    memset(p, 0, sizeof(UA_FindServersOnNetworkResponse));
}

static UA_INLINE UA_FindServersOnNetworkResponse *
UA_FindServersOnNetworkResponse_new(void) {
    return (UA_FindServersOnNetworkResponse*)UA_new(&UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_FindServersOnNetworkResponse_copy(const UA_FindServersOnNetworkResponse *src, UA_FindServersOnNetworkResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKRESPONSE]);
}

static UA_INLINE void
UA_FindServersOnNetworkResponse_deleteMembers(UA_FindServersOnNetworkResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKRESPONSE]);
}

static UA_INLINE void
UA_FindServersOnNetworkResponse_delete(UA_FindServersOnNetworkResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKRESPONSE]);
}

/* RelativePath */
static UA_INLINE void
UA_RelativePath_init(UA_RelativePath *p) {
    memset(p, 0, sizeof(UA_RelativePath));
}

static UA_INLINE UA_RelativePath *
UA_RelativePath_new(void) {
    return (UA_RelativePath*)UA_new(&UA_TYPES[UA_TYPES_RELATIVEPATH]);
}

static UA_INLINE UA_StatusCode
UA_RelativePath_copy(const UA_RelativePath *src, UA_RelativePath *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_RELATIVEPATH]);
}

static UA_INLINE void
UA_RelativePath_deleteMembers(UA_RelativePath *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_RELATIVEPATH]);
}

static UA_INLINE void
UA_RelativePath_delete(UA_RelativePath *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_RELATIVEPATH]);
}

/* RegisterNodesRequest */
static UA_INLINE void
UA_RegisterNodesRequest_init(UA_RegisterNodesRequest *p) {
    memset(p, 0, sizeof(UA_RegisterNodesRequest));
}

static UA_INLINE UA_RegisterNodesRequest *
UA_RegisterNodesRequest_new(void) {
    return (UA_RegisterNodesRequest*)UA_new(&UA_TYPES[UA_TYPES_REGISTERNODESREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_RegisterNodesRequest_copy(const UA_RegisterNodesRequest *src, UA_RegisterNodesRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REGISTERNODESREQUEST]);
}

static UA_INLINE void
UA_RegisterNodesRequest_deleteMembers(UA_RegisterNodesRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REGISTERNODESREQUEST]);
}

static UA_INLINE void
UA_RegisterNodesRequest_delete(UA_RegisterNodesRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REGISTERNODESREQUEST]);
}

/* AggregateConfiguration */
static UA_INLINE void
UA_AggregateConfiguration_init(UA_AggregateConfiguration *p) {
    memset(p, 0, sizeof(UA_AggregateConfiguration));
}

static UA_INLINE UA_AggregateConfiguration *
UA_AggregateConfiguration_new(void) {
    return (UA_AggregateConfiguration*)UA_new(&UA_TYPES[UA_TYPES_AGGREGATECONFIGURATION]);
}

static UA_INLINE UA_StatusCode
UA_AggregateConfiguration_copy(const UA_AggregateConfiguration *src, UA_AggregateConfiguration *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_AggregateConfiguration_deleteMembers(UA_AggregateConfiguration *p) { }

static UA_INLINE void
UA_AggregateConfiguration_delete(UA_AggregateConfiguration *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_AGGREGATECONFIGURATION]);
}

/* DeleteNodesRequest */
static UA_INLINE void
UA_DeleteNodesRequest_init(UA_DeleteNodesRequest *p) {
    memset(p, 0, sizeof(UA_DeleteNodesRequest));
}

static UA_INLINE UA_DeleteNodesRequest *
UA_DeleteNodesRequest_new(void) {
    return (UA_DeleteNodesRequest*)UA_new(&UA_TYPES[UA_TYPES_DELETENODESREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_DeleteNodesRequest_copy(const UA_DeleteNodesRequest *src, UA_DeleteNodesRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETENODESREQUEST]);
}

static UA_INLINE void
UA_DeleteNodesRequest_deleteMembers(UA_DeleteNodesRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETENODESREQUEST]);
}

static UA_INLINE void
UA_DeleteNodesRequest_delete(UA_DeleteNodesRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETENODESREQUEST]);
}

/* PublishResponse */
static UA_INLINE void
UA_PublishResponse_init(UA_PublishResponse *p) {
    memset(p, 0, sizeof(UA_PublishResponse));
}

static UA_INLINE UA_PublishResponse *
UA_PublishResponse_new(void) {
    return (UA_PublishResponse*)UA_new(&UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_PublishResponse_copy(const UA_PublishResponse *src, UA_PublishResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);
}

static UA_INLINE void
UA_PublishResponse_deleteMembers(UA_PublishResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);
}

static UA_INLINE void
UA_PublishResponse_delete(UA_PublishResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_PUBLISHRESPONSE]);
}

/* MonitoredItemModifyRequest */
static UA_INLINE void
UA_MonitoredItemModifyRequest_init(UA_MonitoredItemModifyRequest *p) {
    memset(p, 0, sizeof(UA_MonitoredItemModifyRequest));
}

static UA_INLINE UA_MonitoredItemModifyRequest *
UA_MonitoredItemModifyRequest_new(void) {
    return (UA_MonitoredItemModifyRequest*)UA_new(&UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_MonitoredItemModifyRequest_copy(const UA_MonitoredItemModifyRequest *src, UA_MonitoredItemModifyRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYREQUEST]);
}

static UA_INLINE void
UA_MonitoredItemModifyRequest_deleteMembers(UA_MonitoredItemModifyRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYREQUEST]);
}

static UA_INLINE void
UA_MonitoredItemModifyRequest_delete(UA_MonitoredItemModifyRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MONITOREDITEMMODIFYREQUEST]);
}

/* ServiceCounterDataType */
static UA_INLINE void
UA_ServiceCounterDataType_init(UA_ServiceCounterDataType *p) {
    memset(p, 0, sizeof(UA_ServiceCounterDataType));
}

static UA_INLINE UA_ServiceCounterDataType *
UA_ServiceCounterDataType_new(void) {
    return (UA_ServiceCounterDataType*)UA_new(&UA_TYPES[UA_TYPES_SERVICECOUNTERDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_ServiceCounterDataType_copy(const UA_ServiceCounterDataType *src, UA_ServiceCounterDataType *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_ServiceCounterDataType_deleteMembers(UA_ServiceCounterDataType *p) { }

static UA_INLINE void
UA_ServiceCounterDataType_delete(UA_ServiceCounterDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SERVICECOUNTERDATATYPE]);
}

/* ModelChangeStructureDataType */
static UA_INLINE void
UA_ModelChangeStructureDataType_init(UA_ModelChangeStructureDataType *p) {
    memset(p, 0, sizeof(UA_ModelChangeStructureDataType));
}

static UA_INLINE UA_ModelChangeStructureDataType *
UA_ModelChangeStructureDataType_new(void) {
    return (UA_ModelChangeStructureDataType*)UA_new(&UA_TYPES[UA_TYPES_MODELCHANGESTRUCTUREDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_ModelChangeStructureDataType_copy(const UA_ModelChangeStructureDataType *src, UA_ModelChangeStructureDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MODELCHANGESTRUCTUREDATATYPE]);
}

static UA_INLINE void
UA_ModelChangeStructureDataType_deleteMembers(UA_ModelChangeStructureDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MODELCHANGESTRUCTUREDATATYPE]);
}

static UA_INLINE void
UA_ModelChangeStructureDataType_delete(UA_ModelChangeStructureDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MODELCHANGESTRUCTUREDATATYPE]);
}

/* UserNameIdentityToken */
static UA_INLINE void
UA_UserNameIdentityToken_init(UA_UserNameIdentityToken *p) {
    memset(p, 0, sizeof(UA_UserNameIdentityToken));
}

static UA_INLINE UA_UserNameIdentityToken *
UA_UserNameIdentityToken_new(void) {
    return (UA_UserNameIdentityToken*)UA_new(&UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
}

static UA_INLINE UA_StatusCode
UA_UserNameIdentityToken_copy(const UA_UserNameIdentityToken *src, UA_UserNameIdentityToken *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
}

static UA_INLINE void
UA_UserNameIdentityToken_deleteMembers(UA_UserNameIdentityToken *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
}

static UA_INLINE void
UA_UserNameIdentityToken_delete(UA_UserNameIdentityToken *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]);
}

/* IdType */
static UA_INLINE void
UA_IdType_init(UA_IdType *p) {
    memset(p, 0, sizeof(UA_IdType));
}

static UA_INLINE UA_IdType *
UA_IdType_new(void) {
    return (UA_IdType*)UA_new(&UA_TYPES[UA_TYPES_IDTYPE]);
}

static UA_INLINE UA_StatusCode
UA_IdType_copy(const UA_IdType *src, UA_IdType *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_IdType_deleteMembers(UA_IdType *p) { }

static UA_INLINE void
UA_IdType_delete(UA_IdType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_IDTYPE]);
}

/* UserTokenType */
static UA_INLINE void
UA_UserTokenType_init(UA_UserTokenType *p) {
    memset(p, 0, sizeof(UA_UserTokenType));
}

static UA_INLINE UA_UserTokenType *
UA_UserTokenType_new(void) {
    return (UA_UserTokenType*)UA_new(&UA_TYPES[UA_TYPES_USERTOKENTYPE]);
}

static UA_INLINE UA_StatusCode
UA_UserTokenType_copy(const UA_UserTokenType *src, UA_UserTokenType *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_UserTokenType_deleteMembers(UA_UserTokenType *p) { }

static UA_INLINE void
UA_UserTokenType_delete(UA_UserTokenType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_USERTOKENTYPE]);
}

/* SetTriggeringResponse */
static UA_INLINE void
UA_SetTriggeringResponse_init(UA_SetTriggeringResponse *p) {
    memset(p, 0, sizeof(UA_SetTriggeringResponse));
}

static UA_INLINE UA_SetTriggeringResponse *
UA_SetTriggeringResponse_new(void) {
    return (UA_SetTriggeringResponse*)UA_new(&UA_TYPES[UA_TYPES_SETTRIGGERINGRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_SetTriggeringResponse_copy(const UA_SetTriggeringResponse *src, UA_SetTriggeringResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SETTRIGGERINGRESPONSE]);
}

static UA_INLINE void
UA_SetTriggeringResponse_deleteMembers(UA_SetTriggeringResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SETTRIGGERINGRESPONSE]);
}

static UA_INLINE void
UA_SetTriggeringResponse_delete(UA_SetTriggeringResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SETTRIGGERINGRESPONSE]);
}

/* TimeZoneDataType */
static UA_INLINE void
UA_TimeZoneDataType_init(UA_TimeZoneDataType *p) {
    memset(p, 0, sizeof(UA_TimeZoneDataType));
}

static UA_INLINE UA_TimeZoneDataType *
UA_TimeZoneDataType_new(void) {
    return (UA_TimeZoneDataType*)UA_new(&UA_TYPES[UA_TYPES_TIMEZONEDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_TimeZoneDataType_copy(const UA_TimeZoneDataType *src, UA_TimeZoneDataType *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_TimeZoneDataType_deleteMembers(UA_TimeZoneDataType *p) { }

static UA_INLINE void
UA_TimeZoneDataType_delete(UA_TimeZoneDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_TIMEZONEDATATYPE]);
}

/* ActivateSessionRequest */
static UA_INLINE void
UA_ActivateSessionRequest_init(UA_ActivateSessionRequest *p) {
    memset(p, 0, sizeof(UA_ActivateSessionRequest));
}

static UA_INLINE UA_ActivateSessionRequest *
UA_ActivateSessionRequest_new(void) {
    return (UA_ActivateSessionRequest*)UA_new(&UA_TYPES[UA_TYPES_ACTIVATESESSIONREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_ActivateSessionRequest_copy(const UA_ActivateSessionRequest *src, UA_ActivateSessionRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ACTIVATESESSIONREQUEST]);
}

static UA_INLINE void
UA_ActivateSessionRequest_deleteMembers(UA_ActivateSessionRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ACTIVATESESSIONREQUEST]);
}

static UA_INLINE void
UA_ActivateSessionRequest_delete(UA_ActivateSessionRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ACTIVATESESSIONREQUEST]);
}

/* OpenSecureChannelResponse */
static UA_INLINE void
UA_OpenSecureChannelResponse_init(UA_OpenSecureChannelResponse *p) {
    memset(p, 0, sizeof(UA_OpenSecureChannelResponse));
}

static UA_INLINE UA_OpenSecureChannelResponse *
UA_OpenSecureChannelResponse_new(void) {
    return (UA_OpenSecureChannelResponse*)UA_new(&UA_TYPES[UA_TYPES_OPENSECURECHANNELRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_OpenSecureChannelResponse_copy(const UA_OpenSecureChannelResponse *src, UA_OpenSecureChannelResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_OPENSECURECHANNELRESPONSE]);
}

static UA_INLINE void
UA_OpenSecureChannelResponse_deleteMembers(UA_OpenSecureChannelResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_OPENSECURECHANNELRESPONSE]);
}

static UA_INLINE void
UA_OpenSecureChannelResponse_delete(UA_OpenSecureChannelResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_OPENSECURECHANNELRESPONSE]);
}

/* ApplicationType */
static UA_INLINE void
UA_ApplicationType_init(UA_ApplicationType *p) {
    memset(p, 0, sizeof(UA_ApplicationType));
}

static UA_INLINE UA_ApplicationType *
UA_ApplicationType_new(void) {
    return (UA_ApplicationType*)UA_new(&UA_TYPES[UA_TYPES_APPLICATIONTYPE]);
}

static UA_INLINE UA_StatusCode
UA_ApplicationType_copy(const UA_ApplicationType *src, UA_ApplicationType *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_ApplicationType_deleteMembers(UA_ApplicationType *p) { }

static UA_INLINE void
UA_ApplicationType_delete(UA_ApplicationType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_APPLICATIONTYPE]);
}

/* ServerState */
static UA_INLINE void
UA_ServerState_init(UA_ServerState *p) {
    memset(p, 0, sizeof(UA_ServerState));
}

static UA_INLINE UA_ServerState *
UA_ServerState_new(void) {
    return (UA_ServerState*)UA_new(&UA_TYPES[UA_TYPES_SERVERSTATE]);
}

static UA_INLINE UA_StatusCode
UA_ServerState_copy(const UA_ServerState *src, UA_ServerState *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_ServerState_deleteMembers(UA_ServerState *p) { }

static UA_INLINE void
UA_ServerState_delete(UA_ServerState *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SERVERSTATE]);
}

/* QueryNextResponse */
static UA_INLINE void
UA_QueryNextResponse_init(UA_QueryNextResponse *p) {
    memset(p, 0, sizeof(UA_QueryNextResponse));
}

static UA_INLINE UA_QueryNextResponse *
UA_QueryNextResponse_new(void) {
    return (UA_QueryNextResponse*)UA_new(&UA_TYPES[UA_TYPES_QUERYNEXTRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_QueryNextResponse_copy(const UA_QueryNextResponse *src, UA_QueryNextResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_QUERYNEXTRESPONSE]);
}

static UA_INLINE void
UA_QueryNextResponse_deleteMembers(UA_QueryNextResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_QUERYNEXTRESPONSE]);
}

static UA_INLINE void
UA_QueryNextResponse_delete(UA_QueryNextResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_QUERYNEXTRESPONSE]);
}

/* DiscoveryConfiguration */
static UA_INLINE void
UA_DiscoveryConfiguration_init(UA_DiscoveryConfiguration *p) {
    memset(p, 0, sizeof(UA_DiscoveryConfiguration));
}

static UA_INLINE UA_DiscoveryConfiguration *
UA_DiscoveryConfiguration_new(void) {
    return (UA_DiscoveryConfiguration*)UA_new(&UA_TYPES[UA_TYPES_DISCOVERYCONFIGURATION]);
}

static UA_INLINE UA_StatusCode
UA_DiscoveryConfiguration_copy(const UA_DiscoveryConfiguration *src, UA_DiscoveryConfiguration *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_DiscoveryConfiguration_deleteMembers(UA_DiscoveryConfiguration *p) { }

static UA_INLINE void
UA_DiscoveryConfiguration_delete(UA_DiscoveryConfiguration *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DISCOVERYCONFIGURATION]);
}

/* ActivateSessionResponse */
static UA_INLINE void
UA_ActivateSessionResponse_init(UA_ActivateSessionResponse *p) {
    memset(p, 0, sizeof(UA_ActivateSessionResponse));
}

static UA_INLINE UA_ActivateSessionResponse *
UA_ActivateSessionResponse_new(void) {
    return (UA_ActivateSessionResponse*)UA_new(&UA_TYPES[UA_TYPES_ACTIVATESESSIONRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_ActivateSessionResponse_copy(const UA_ActivateSessionResponse *src, UA_ActivateSessionResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ACTIVATESESSIONRESPONSE]);
}

static UA_INLINE void
UA_ActivateSessionResponse_deleteMembers(UA_ActivateSessionResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ACTIVATESESSIONRESPONSE]);
}

static UA_INLINE void
UA_ActivateSessionResponse_delete(UA_ActivateSessionResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ACTIVATESESSIONRESPONSE]);
}

/* EndpointUrlListDataType */
static UA_INLINE void
UA_EndpointUrlListDataType_init(UA_EndpointUrlListDataType *p) {
    memset(p, 0, sizeof(UA_EndpointUrlListDataType));
}

static UA_INLINE UA_EndpointUrlListDataType *
UA_EndpointUrlListDataType_new(void) {
    return (UA_EndpointUrlListDataType*)UA_new(&UA_TYPES[UA_TYPES_ENDPOINTURLLISTDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_EndpointUrlListDataType_copy(const UA_EndpointUrlListDataType *src, UA_EndpointUrlListDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ENDPOINTURLLISTDATATYPE]);
}

static UA_INLINE void
UA_EndpointUrlListDataType_deleteMembers(UA_EndpointUrlListDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ENDPOINTURLLISTDATATYPE]);
}

static UA_INLINE void
UA_EndpointUrlListDataType_delete(UA_EndpointUrlListDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ENDPOINTURLLISTDATATYPE]);
}

/* FilterOperator */
static UA_INLINE void
UA_FilterOperator_init(UA_FilterOperator *p) {
    memset(p, 0, sizeof(UA_FilterOperator));
}

static UA_INLINE UA_FilterOperator *
UA_FilterOperator_new(void) {
    return (UA_FilterOperator*)UA_new(&UA_TYPES[UA_TYPES_FILTEROPERATOR]);
}

static UA_INLINE UA_StatusCode
UA_FilterOperator_copy(const UA_FilterOperator *src, UA_FilterOperator *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_FilterOperator_deleteMembers(UA_FilterOperator *p) { }

static UA_INLINE void
UA_FilterOperator_delete(UA_FilterOperator *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_FILTEROPERATOR]);
}

/* QueryNextRequest */
static UA_INLINE void
UA_QueryNextRequest_init(UA_QueryNextRequest *p) {
    memset(p, 0, sizeof(UA_QueryNextRequest));
}

static UA_INLINE UA_QueryNextRequest *
UA_QueryNextRequest_new(void) {
    return (UA_QueryNextRequest*)UA_new(&UA_TYPES[UA_TYPES_QUERYNEXTREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_QueryNextRequest_copy(const UA_QueryNextRequest *src, UA_QueryNextRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_QUERYNEXTREQUEST]);
}

static UA_INLINE void
UA_QueryNextRequest_deleteMembers(UA_QueryNextRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_QUERYNEXTREQUEST]);
}

static UA_INLINE void
UA_QueryNextRequest_delete(UA_QueryNextRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_QUERYNEXTREQUEST]);
}

/* WriteResponse */
static UA_INLINE void
UA_WriteResponse_init(UA_WriteResponse *p) {
    memset(p, 0, sizeof(UA_WriteResponse));
}

static UA_INLINE UA_WriteResponse *
UA_WriteResponse_new(void) {
    return (UA_WriteResponse*)UA_new(&UA_TYPES[UA_TYPES_WRITERESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_WriteResponse_copy(const UA_WriteResponse *src, UA_WriteResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_WRITERESPONSE]);
}

static UA_INLINE void
UA_WriteResponse_deleteMembers(UA_WriteResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_WRITERESPONSE]);
}

static UA_INLINE void
UA_WriteResponse_delete(UA_WriteResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_WRITERESPONSE]);
}

/* BrowseNextRequest */
static UA_INLINE void
UA_BrowseNextRequest_init(UA_BrowseNextRequest *p) {
    memset(p, 0, sizeof(UA_BrowseNextRequest));
}

static UA_INLINE UA_BrowseNextRequest *
UA_BrowseNextRequest_new(void) {
    return (UA_BrowseNextRequest*)UA_new(&UA_TYPES[UA_TYPES_BROWSENEXTREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_BrowseNextRequest_copy(const UA_BrowseNextRequest *src, UA_BrowseNextRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSENEXTREQUEST]);
}

static UA_INLINE void
UA_BrowseNextRequest_deleteMembers(UA_BrowseNextRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSENEXTREQUEST]);
}

static UA_INLINE void
UA_BrowseNextRequest_delete(UA_BrowseNextRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSENEXTREQUEST]);
}

/* CreateSubscriptionRequest */
static UA_INLINE void
UA_CreateSubscriptionRequest_init(UA_CreateSubscriptionRequest *p) {
    memset(p, 0, sizeof(UA_CreateSubscriptionRequest));
}

static UA_INLINE UA_CreateSubscriptionRequest *
UA_CreateSubscriptionRequest_new(void) {
    return (UA_CreateSubscriptionRequest*)UA_new(&UA_TYPES[UA_TYPES_CREATESUBSCRIPTIONREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_CreateSubscriptionRequest_copy(const UA_CreateSubscriptionRequest *src, UA_CreateSubscriptionRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CREATESUBSCRIPTIONREQUEST]);
}

static UA_INLINE void
UA_CreateSubscriptionRequest_deleteMembers(UA_CreateSubscriptionRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CREATESUBSCRIPTIONREQUEST]);
}

static UA_INLINE void
UA_CreateSubscriptionRequest_delete(UA_CreateSubscriptionRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CREATESUBSCRIPTIONREQUEST]);
}

/* VariableTypeAttributes */
static UA_INLINE void
UA_VariableTypeAttributes_init(UA_VariableTypeAttributes *p) {
    memset(p, 0, sizeof(UA_VariableTypeAttributes));
}

static UA_INLINE UA_VariableTypeAttributes *
UA_VariableTypeAttributes_new(void) {
    return (UA_VariableTypeAttributes*)UA_new(&UA_TYPES[UA_TYPES_VARIABLETYPEATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_VariableTypeAttributes_copy(const UA_VariableTypeAttributes *src, UA_VariableTypeAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_VARIABLETYPEATTRIBUTES]);
}

static UA_INLINE void
UA_VariableTypeAttributes_deleteMembers(UA_VariableTypeAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_VARIABLETYPEATTRIBUTES]);
}

static UA_INLINE void
UA_VariableTypeAttributes_delete(UA_VariableTypeAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_VARIABLETYPEATTRIBUTES]);
}

/* BrowsePathResult */
static UA_INLINE void
UA_BrowsePathResult_init(UA_BrowsePathResult *p) {
    memset(p, 0, sizeof(UA_BrowsePathResult));
}

static UA_INLINE UA_BrowsePathResult *
UA_BrowsePathResult_new(void) {
    return (UA_BrowsePathResult*)UA_new(&UA_TYPES[UA_TYPES_BROWSEPATHRESULT]);
}

static UA_INLINE UA_StatusCode
UA_BrowsePathResult_copy(const UA_BrowsePathResult *src, UA_BrowsePathResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSEPATHRESULT]);
}

static UA_INLINE void
UA_BrowsePathResult_deleteMembers(UA_BrowsePathResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSEPATHRESULT]);
}

static UA_INLINE void
UA_BrowsePathResult_delete(UA_BrowsePathResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSEPATHRESULT]);
}

/* ModifySubscriptionResponse */
static UA_INLINE void
UA_ModifySubscriptionResponse_init(UA_ModifySubscriptionResponse *p) {
    memset(p, 0, sizeof(UA_ModifySubscriptionResponse));
}

static UA_INLINE UA_ModifySubscriptionResponse *
UA_ModifySubscriptionResponse_new(void) {
    return (UA_ModifySubscriptionResponse*)UA_new(&UA_TYPES[UA_TYPES_MODIFYSUBSCRIPTIONRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_ModifySubscriptionResponse_copy(const UA_ModifySubscriptionResponse *src, UA_ModifySubscriptionResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MODIFYSUBSCRIPTIONRESPONSE]);
}

static UA_INLINE void
UA_ModifySubscriptionResponse_deleteMembers(UA_ModifySubscriptionResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MODIFYSUBSCRIPTIONRESPONSE]);
}

static UA_INLINE void
UA_ModifySubscriptionResponse_delete(UA_ModifySubscriptionResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MODIFYSUBSCRIPTIONRESPONSE]);
}

/* RedundantServerDataType */
static UA_INLINE void
UA_RedundantServerDataType_init(UA_RedundantServerDataType *p) {
    memset(p, 0, sizeof(UA_RedundantServerDataType));
}

static UA_INLINE UA_RedundantServerDataType *
UA_RedundantServerDataType_new(void) {
    return (UA_RedundantServerDataType*)UA_new(&UA_TYPES[UA_TYPES_REDUNDANTSERVERDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_RedundantServerDataType_copy(const UA_RedundantServerDataType *src, UA_RedundantServerDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REDUNDANTSERVERDATATYPE]);
}

static UA_INLINE void
UA_RedundantServerDataType_deleteMembers(UA_RedundantServerDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REDUNDANTSERVERDATATYPE]);
}

static UA_INLINE void
UA_RedundantServerDataType_delete(UA_RedundantServerDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REDUNDANTSERVERDATATYPE]);
}

/* RegisterNodesResponse */
static UA_INLINE void
UA_RegisterNodesResponse_init(UA_RegisterNodesResponse *p) {
    memset(p, 0, sizeof(UA_RegisterNodesResponse));
}

static UA_INLINE UA_RegisterNodesResponse *
UA_RegisterNodesResponse_new(void) {
    return (UA_RegisterNodesResponse*)UA_new(&UA_TYPES[UA_TYPES_REGISTERNODESRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_RegisterNodesResponse_copy(const UA_RegisterNodesResponse *src, UA_RegisterNodesResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REGISTERNODESRESPONSE]);
}

static UA_INLINE void
UA_RegisterNodesResponse_deleteMembers(UA_RegisterNodesResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REGISTERNODESRESPONSE]);
}

static UA_INLINE void
UA_RegisterNodesResponse_delete(UA_RegisterNodesResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REGISTERNODESRESPONSE]);
}

/* CloseSessionRequest */
static UA_INLINE void
UA_CloseSessionRequest_init(UA_CloseSessionRequest *p) {
    memset(p, 0, sizeof(UA_CloseSessionRequest));
}

static UA_INLINE UA_CloseSessionRequest *
UA_CloseSessionRequest_new(void) {
    return (UA_CloseSessionRequest*)UA_new(&UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_CloseSessionRequest_copy(const UA_CloseSessionRequest *src, UA_CloseSessionRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST]);
}

static UA_INLINE void
UA_CloseSessionRequest_deleteMembers(UA_CloseSessionRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST]);
}

static UA_INLINE void
UA_CloseSessionRequest_delete(UA_CloseSessionRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST]);
}

/* ModifyMonitoredItemsResponse */
static UA_INLINE void
UA_ModifyMonitoredItemsResponse_init(UA_ModifyMonitoredItemsResponse *p) {
    memset(p, 0, sizeof(UA_ModifyMonitoredItemsResponse));
}

static UA_INLINE UA_ModifyMonitoredItemsResponse *
UA_ModifyMonitoredItemsResponse_new(void) {
    return (UA_ModifyMonitoredItemsResponse*)UA_new(&UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_ModifyMonitoredItemsResponse_copy(const UA_ModifyMonitoredItemsResponse *src, UA_ModifyMonitoredItemsResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSRESPONSE]);
}

static UA_INLINE void
UA_ModifyMonitoredItemsResponse_deleteMembers(UA_ModifyMonitoredItemsResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSRESPONSE]);
}

static UA_INLINE void
UA_ModifyMonitoredItemsResponse_delete(UA_ModifyMonitoredItemsResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSRESPONSE]);
}

/* ModifySubscriptionRequest */
static UA_INLINE void
UA_ModifySubscriptionRequest_init(UA_ModifySubscriptionRequest *p) {
    memset(p, 0, sizeof(UA_ModifySubscriptionRequest));
}

static UA_INLINE UA_ModifySubscriptionRequest *
UA_ModifySubscriptionRequest_new(void) {
    return (UA_ModifySubscriptionRequest*)UA_new(&UA_TYPES[UA_TYPES_MODIFYSUBSCRIPTIONREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_ModifySubscriptionRequest_copy(const UA_ModifySubscriptionRequest *src, UA_ModifySubscriptionRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MODIFYSUBSCRIPTIONREQUEST]);
}

static UA_INLINE void
UA_ModifySubscriptionRequest_deleteMembers(UA_ModifySubscriptionRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MODIFYSUBSCRIPTIONREQUEST]);
}

static UA_INLINE void
UA_ModifySubscriptionRequest_delete(UA_ModifySubscriptionRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MODIFYSUBSCRIPTIONREQUEST]);
}

/* ServerDiagnosticsSummaryDataType */
static UA_INLINE void
UA_ServerDiagnosticsSummaryDataType_init(UA_ServerDiagnosticsSummaryDataType *p) {
    memset(p, 0, sizeof(UA_ServerDiagnosticsSummaryDataType));
}

static UA_INLINE UA_ServerDiagnosticsSummaryDataType *
UA_ServerDiagnosticsSummaryDataType_new(void) {
    return (UA_ServerDiagnosticsSummaryDataType*)UA_new(&UA_TYPES[UA_TYPES_SERVERDIAGNOSTICSSUMMARYDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_ServerDiagnosticsSummaryDataType_copy(const UA_ServerDiagnosticsSummaryDataType *src, UA_ServerDiagnosticsSummaryDataType *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_ServerDiagnosticsSummaryDataType_deleteMembers(UA_ServerDiagnosticsSummaryDataType *p) { }

static UA_INLINE void
UA_ServerDiagnosticsSummaryDataType_delete(UA_ServerDiagnosticsSummaryDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SERVERDIAGNOSTICSSUMMARYDATATYPE]);
}

/* UserTokenPolicy */
static UA_INLINE void
UA_UserTokenPolicy_init(UA_UserTokenPolicy *p) {
    memset(p, 0, sizeof(UA_UserTokenPolicy));
}

static UA_INLINE UA_UserTokenPolicy *
UA_UserTokenPolicy_new(void) {
    return (UA_UserTokenPolicy*)UA_new(&UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
}

static UA_INLINE UA_StatusCode
UA_UserTokenPolicy_copy(const UA_UserTokenPolicy *src, UA_UserTokenPolicy *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
}

static UA_INLINE void
UA_UserTokenPolicy_deleteMembers(UA_UserTokenPolicy *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
}

static UA_INLINE void
UA_UserTokenPolicy_delete(UA_UserTokenPolicy *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
}

/* ReferenceTypeAttributes */
static UA_INLINE void
UA_ReferenceTypeAttributes_init(UA_ReferenceTypeAttributes *p) {
    memset(p, 0, sizeof(UA_ReferenceTypeAttributes));
}

static UA_INLINE UA_ReferenceTypeAttributes *
UA_ReferenceTypeAttributes_new(void) {
    return (UA_ReferenceTypeAttributes*)UA_new(&UA_TYPES[UA_TYPES_REFERENCETYPEATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_ReferenceTypeAttributes_copy(const UA_ReferenceTypeAttributes *src, UA_ReferenceTypeAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REFERENCETYPEATTRIBUTES]);
}

static UA_INLINE void
UA_ReferenceTypeAttributes_deleteMembers(UA_ReferenceTypeAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REFERENCETYPEATTRIBUTES]);
}

static UA_INLINE void
UA_ReferenceTypeAttributes_delete(UA_ReferenceTypeAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REFERENCETYPEATTRIBUTES]);
}

/* BrowsePath */
static UA_INLINE void
UA_BrowsePath_init(UA_BrowsePath *p) {
    memset(p, 0, sizeof(UA_BrowsePath));
}

static UA_INLINE UA_BrowsePath *
UA_BrowsePath_new(void) {
    return (UA_BrowsePath*)UA_new(&UA_TYPES[UA_TYPES_BROWSEPATH]);
}

static UA_INLINE UA_StatusCode
UA_BrowsePath_copy(const UA_BrowsePath *src, UA_BrowsePath *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSEPATH]);
}

static UA_INLINE void
UA_BrowsePath_deleteMembers(UA_BrowsePath *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSEPATH]);
}

static UA_INLINE void
UA_BrowsePath_delete(UA_BrowsePath *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSEPATH]);
}

/* SetMonitoringModeRequest */
static UA_INLINE void
UA_SetMonitoringModeRequest_init(UA_SetMonitoringModeRequest *p) {
    memset(p, 0, sizeof(UA_SetMonitoringModeRequest));
}

static UA_INLINE UA_SetMonitoringModeRequest *
UA_SetMonitoringModeRequest_new(void) {
    return (UA_SetMonitoringModeRequest*)UA_new(&UA_TYPES[UA_TYPES_SETMONITORINGMODEREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_SetMonitoringModeRequest_copy(const UA_SetMonitoringModeRequest *src, UA_SetMonitoringModeRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SETMONITORINGMODEREQUEST]);
}

static UA_INLINE void
UA_SetMonitoringModeRequest_deleteMembers(UA_SetMonitoringModeRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SETMONITORINGMODEREQUEST]);
}

static UA_INLINE void
UA_SetMonitoringModeRequest_delete(UA_SetMonitoringModeRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SETMONITORINGMODEREQUEST]);
}

/* UnregisterNodesResponse */
static UA_INLINE void
UA_UnregisterNodesResponse_init(UA_UnregisterNodesResponse *p) {
    memset(p, 0, sizeof(UA_UnregisterNodesResponse));
}

static UA_INLINE UA_UnregisterNodesResponse *
UA_UnregisterNodesResponse_new(void) {
    return (UA_UnregisterNodesResponse*)UA_new(&UA_TYPES[UA_TYPES_UNREGISTERNODESRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_UnregisterNodesResponse_copy(const UA_UnregisterNodesResponse *src, UA_UnregisterNodesResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_UNREGISTERNODESRESPONSE]);
}

static UA_INLINE void
UA_UnregisterNodesResponse_deleteMembers(UA_UnregisterNodesResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_UNREGISTERNODESRESPONSE]);
}

static UA_INLINE void
UA_UnregisterNodesResponse_delete(UA_UnregisterNodesResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_UNREGISTERNODESRESPONSE]);
}

/* WriteRequest */
static UA_INLINE void
UA_WriteRequest_init(UA_WriteRequest *p) {
    memset(p, 0, sizeof(UA_WriteRequest));
}

static UA_INLINE UA_WriteRequest *
UA_WriteRequest_new(void) {
    return (UA_WriteRequest*)UA_new(&UA_TYPES[UA_TYPES_WRITEREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_WriteRequest_copy(const UA_WriteRequest *src, UA_WriteRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_WRITEREQUEST]);
}

static UA_INLINE void
UA_WriteRequest_deleteMembers(UA_WriteRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_WRITEREQUEST]);
}

static UA_INLINE void
UA_WriteRequest_delete(UA_WriteRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_WRITEREQUEST]);
}

/* ObjectAttributes */
static UA_INLINE void
UA_ObjectAttributes_init(UA_ObjectAttributes *p) {
    memset(p, 0, sizeof(UA_ObjectAttributes));
}

static UA_INLINE UA_ObjectAttributes *
UA_ObjectAttributes_new(void) {
    return (UA_ObjectAttributes*)UA_new(&UA_TYPES[UA_TYPES_OBJECTATTRIBUTES]);
}

static UA_INLINE UA_StatusCode
UA_ObjectAttributes_copy(const UA_ObjectAttributes *src, UA_ObjectAttributes *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES]);
}

static UA_INLINE void
UA_ObjectAttributes_deleteMembers(UA_ObjectAttributes *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES]);
}

static UA_INLINE void
UA_ObjectAttributes_delete(UA_ObjectAttributes *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES]);
}

/* BrowseResultMask */
static UA_INLINE void
UA_BrowseResultMask_init(UA_BrowseResultMask *p) {
    memset(p, 0, sizeof(UA_BrowseResultMask));
}

static UA_INLINE UA_BrowseResultMask *
UA_BrowseResultMask_new(void) {
    return (UA_BrowseResultMask*)UA_new(&UA_TYPES[UA_TYPES_BROWSERESULTMASK]);
}

static UA_INLINE UA_StatusCode
UA_BrowseResultMask_copy(const UA_BrowseResultMask *src, UA_BrowseResultMask *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_BrowseResultMask_deleteMembers(UA_BrowseResultMask *p) { }

static UA_INLINE void
UA_BrowseResultMask_delete(UA_BrowseResultMask *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSERESULTMASK]);
}

/* BrowseDescription */
static UA_INLINE void
UA_BrowseDescription_init(UA_BrowseDescription *p) {
    memset(p, 0, sizeof(UA_BrowseDescription));
}

static UA_INLINE UA_BrowseDescription *
UA_BrowseDescription_new(void) {
    return (UA_BrowseDescription*)UA_new(&UA_TYPES[UA_TYPES_BROWSEDESCRIPTION]);
}

static UA_INLINE UA_StatusCode
UA_BrowseDescription_copy(const UA_BrowseDescription *src, UA_BrowseDescription *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSEDESCRIPTION]);
}

static UA_INLINE void
UA_BrowseDescription_deleteMembers(UA_BrowseDescription *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSEDESCRIPTION]);
}

static UA_INLINE void
UA_BrowseDescription_delete(UA_BrowseDescription *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSEDESCRIPTION]);
}

/* SetTriggeringRequest */
static UA_INLINE void
UA_SetTriggeringRequest_init(UA_SetTriggeringRequest *p) {
    memset(p, 0, sizeof(UA_SetTriggeringRequest));
}

static UA_INLINE UA_SetTriggeringRequest *
UA_SetTriggeringRequest_new(void) {
    return (UA_SetTriggeringRequest*)UA_new(&UA_TYPES[UA_TYPES_SETTRIGGERINGREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_SetTriggeringRequest_copy(const UA_SetTriggeringRequest *src, UA_SetTriggeringRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SETTRIGGERINGREQUEST]);
}

static UA_INLINE void
UA_SetTriggeringRequest_deleteMembers(UA_SetTriggeringRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SETTRIGGERINGREQUEST]);
}

static UA_INLINE void
UA_SetTriggeringRequest_delete(UA_SetTriggeringRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SETTRIGGERINGREQUEST]);
}

/* SessionSecurityDiagnosticsDataType */
static UA_INLINE void
UA_SessionSecurityDiagnosticsDataType_init(UA_SessionSecurityDiagnosticsDataType *p) {
    memset(p, 0, sizeof(UA_SessionSecurityDiagnosticsDataType));
}

static UA_INLINE UA_SessionSecurityDiagnosticsDataType *
UA_SessionSecurityDiagnosticsDataType_new(void) {
    return (UA_SessionSecurityDiagnosticsDataType*)UA_new(&UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_SessionSecurityDiagnosticsDataType_copy(const UA_SessionSecurityDiagnosticsDataType *src, UA_SessionSecurityDiagnosticsDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE]);
}

static UA_INLINE void
UA_SessionSecurityDiagnosticsDataType_deleteMembers(UA_SessionSecurityDiagnosticsDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE]);
}

static UA_INLINE void
UA_SessionSecurityDiagnosticsDataType_delete(UA_SessionSecurityDiagnosticsDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SESSIONSECURITYDIAGNOSTICSDATATYPE]);
}

/* RepublishRequest */
static UA_INLINE void
UA_RepublishRequest_init(UA_RepublishRequest *p) {
    memset(p, 0, sizeof(UA_RepublishRequest));
}

static UA_INLINE UA_RepublishRequest *
UA_RepublishRequest_new(void) {
    return (UA_RepublishRequest*)UA_new(&UA_TYPES[UA_TYPES_REPUBLISHREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_RepublishRequest_copy(const UA_RepublishRequest *src, UA_RepublishRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REPUBLISHREQUEST]);
}

static UA_INLINE void
UA_RepublishRequest_deleteMembers(UA_RepublishRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REPUBLISHREQUEST]);
}

static UA_INLINE void
UA_RepublishRequest_delete(UA_RepublishRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REPUBLISHREQUEST]);
}

/* GetEndpointsRequest */
static UA_INLINE void
UA_GetEndpointsRequest_init(UA_GetEndpointsRequest *p) {
    memset(p, 0, sizeof(UA_GetEndpointsRequest));
}

static UA_INLINE UA_GetEndpointsRequest *
UA_GetEndpointsRequest_new(void) {
    return (UA_GetEndpointsRequest*)UA_new(&UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_GetEndpointsRequest_copy(const UA_GetEndpointsRequest *src, UA_GetEndpointsRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST]);
}

static UA_INLINE void
UA_GetEndpointsRequest_deleteMembers(UA_GetEndpointsRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST]);
}

static UA_INLINE void
UA_GetEndpointsRequest_delete(UA_GetEndpointsRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST]);
}

/* PublishRequest */
static UA_INLINE void
UA_PublishRequest_init(UA_PublishRequest *p) {
    memset(p, 0, sizeof(UA_PublishRequest));
}

static UA_INLINE UA_PublishRequest *
UA_PublishRequest_new(void) {
    return (UA_PublishRequest*)UA_new(&UA_TYPES[UA_TYPES_PUBLISHREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_PublishRequest_copy(const UA_PublishRequest *src, UA_PublishRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_PUBLISHREQUEST]);
}

static UA_INLINE void
UA_PublishRequest_deleteMembers(UA_PublishRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_PUBLISHREQUEST]);
}

static UA_INLINE void
UA_PublishRequest_delete(UA_PublishRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_PUBLISHREQUEST]);
}

/* DeleteSubscriptionsResponse */
static UA_INLINE void
UA_DeleteSubscriptionsResponse_init(UA_DeleteSubscriptionsResponse *p) {
    memset(p, 0, sizeof(UA_DeleteSubscriptionsResponse));
}

static UA_INLINE UA_DeleteSubscriptionsResponse *
UA_DeleteSubscriptionsResponse_new(void) {
    return (UA_DeleteSubscriptionsResponse*)UA_new(&UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_DeleteSubscriptionsResponse_copy(const UA_DeleteSubscriptionsResponse *src, UA_DeleteSubscriptionsResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSRESPONSE]);
}

static UA_INLINE void
UA_DeleteSubscriptionsResponse_deleteMembers(UA_DeleteSubscriptionsResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSRESPONSE]);
}

static UA_INLINE void
UA_DeleteSubscriptionsResponse_delete(UA_DeleteSubscriptionsResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETESUBSCRIPTIONSRESPONSE]);
}

/* AddNodesResponse */
static UA_INLINE void
UA_AddNodesResponse_init(UA_AddNodesResponse *p) {
    memset(p, 0, sizeof(UA_AddNodesResponse));
}

static UA_INLINE UA_AddNodesResponse *
UA_AddNodesResponse_new(void) {
    return (UA_AddNodesResponse*)UA_new(&UA_TYPES[UA_TYPES_ADDNODESRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_AddNodesResponse_copy(const UA_AddNodesResponse *src, UA_AddNodesResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ADDNODESRESPONSE]);
}

static UA_INLINE void
UA_AddNodesResponse_deleteMembers(UA_AddNodesResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ADDNODESRESPONSE]);
}

static UA_INLINE void
UA_AddNodesResponse_delete(UA_AddNodesResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ADDNODESRESPONSE]);
}

/* DataChangeNotification */
static UA_INLINE void
UA_DataChangeNotification_init(UA_DataChangeNotification *p) {
    memset(p, 0, sizeof(UA_DataChangeNotification));
}

static UA_INLINE UA_DataChangeNotification *
UA_DataChangeNotification_new(void) {
    return (UA_DataChangeNotification*)UA_new(&UA_TYPES[UA_TYPES_DATACHANGENOTIFICATION]);
}

static UA_INLINE UA_StatusCode
UA_DataChangeNotification_copy(const UA_DataChangeNotification *src, UA_DataChangeNotification *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DATACHANGENOTIFICATION]);
}

static UA_INLINE void
UA_DataChangeNotification_deleteMembers(UA_DataChangeNotification *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DATACHANGENOTIFICATION]);
}

static UA_INLINE void
UA_DataChangeNotification_delete(UA_DataChangeNotification *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DATACHANGENOTIFICATION]);
}

/* CloseSecureChannelResponse */
static UA_INLINE void
UA_CloseSecureChannelResponse_init(UA_CloseSecureChannelResponse *p) {
    memset(p, 0, sizeof(UA_CloseSecureChannelResponse));
}

static UA_INLINE UA_CloseSecureChannelResponse *
UA_CloseSecureChannelResponse_new(void) {
    return (UA_CloseSecureChannelResponse*)UA_new(&UA_TYPES[UA_TYPES_CLOSESECURECHANNELRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_CloseSecureChannelResponse_copy(const UA_CloseSecureChannelResponse *src, UA_CloseSecureChannelResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CLOSESECURECHANNELRESPONSE]);
}

static UA_INLINE void
UA_CloseSecureChannelResponse_deleteMembers(UA_CloseSecureChannelResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CLOSESECURECHANNELRESPONSE]);
}

static UA_INLINE void
UA_CloseSecureChannelResponse_delete(UA_CloseSecureChannelResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CLOSESECURECHANNELRESPONSE]);
}

/* ModifyMonitoredItemsRequest */
static UA_INLINE void
UA_ModifyMonitoredItemsRequest_init(UA_ModifyMonitoredItemsRequest *p) {
    memset(p, 0, sizeof(UA_ModifyMonitoredItemsRequest));
}

static UA_INLINE UA_ModifyMonitoredItemsRequest *
UA_ModifyMonitoredItemsRequest_new(void) {
    return (UA_ModifyMonitoredItemsRequest*)UA_new(&UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_ModifyMonitoredItemsRequest_copy(const UA_ModifyMonitoredItemsRequest *src, UA_ModifyMonitoredItemsRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSREQUEST]);
}

static UA_INLINE void
UA_ModifyMonitoredItemsRequest_deleteMembers(UA_ModifyMonitoredItemsRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSREQUEST]);
}

static UA_INLINE void
UA_ModifyMonitoredItemsRequest_delete(UA_ModifyMonitoredItemsRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSREQUEST]);
}

/* SetMonitoringModeResponse */
static UA_INLINE void
UA_SetMonitoringModeResponse_init(UA_SetMonitoringModeResponse *p) {
    memset(p, 0, sizeof(UA_SetMonitoringModeResponse));
}

static UA_INLINE UA_SetMonitoringModeResponse *
UA_SetMonitoringModeResponse_new(void) {
    return (UA_SetMonitoringModeResponse*)UA_new(&UA_TYPES[UA_TYPES_SETMONITORINGMODERESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_SetMonitoringModeResponse_copy(const UA_SetMonitoringModeResponse *src, UA_SetMonitoringModeResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SETMONITORINGMODERESPONSE]);
}

static UA_INLINE void
UA_SetMonitoringModeResponse_deleteMembers(UA_SetMonitoringModeResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SETMONITORINGMODERESPONSE]);
}

static UA_INLINE void
UA_SetMonitoringModeResponse_delete(UA_SetMonitoringModeResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SETMONITORINGMODERESPONSE]);
}

/* FindServersRequest */
static UA_INLINE void
UA_FindServersRequest_init(UA_FindServersRequest *p) {
    memset(p, 0, sizeof(UA_FindServersRequest));
}

static UA_INLINE UA_FindServersRequest *
UA_FindServersRequest_new(void) {
    return (UA_FindServersRequest*)UA_new(&UA_TYPES[UA_TYPES_FINDSERVERSREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_FindServersRequest_copy(const UA_FindServersRequest *src, UA_FindServersRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_FINDSERVERSREQUEST]);
}

static UA_INLINE void
UA_FindServersRequest_deleteMembers(UA_FindServersRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_FINDSERVERSREQUEST]);
}

static UA_INLINE void
UA_FindServersRequest_delete(UA_FindServersRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_FINDSERVERSREQUEST]);
}

/* ReferenceDescription */
static UA_INLINE void
UA_ReferenceDescription_init(UA_ReferenceDescription *p) {
    memset(p, 0, sizeof(UA_ReferenceDescription));
}

static UA_INLINE UA_ReferenceDescription *
UA_ReferenceDescription_new(void) {
    return (UA_ReferenceDescription*)UA_new(&UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
}

static UA_INLINE UA_StatusCode
UA_ReferenceDescription_copy(const UA_ReferenceDescription *src, UA_ReferenceDescription *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
}

static UA_INLINE void
UA_ReferenceDescription_deleteMembers(UA_ReferenceDescription *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
}

static UA_INLINE void
UA_ReferenceDescription_delete(UA_ReferenceDescription *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REFERENCEDESCRIPTION]);
}

/* SetPublishingModeResponse */
static UA_INLINE void
UA_SetPublishingModeResponse_init(UA_SetPublishingModeResponse *p) {
    memset(p, 0, sizeof(UA_SetPublishingModeResponse));
}

static UA_INLINE UA_SetPublishingModeResponse *
UA_SetPublishingModeResponse_new(void) {
    return (UA_SetPublishingModeResponse*)UA_new(&UA_TYPES[UA_TYPES_SETPUBLISHINGMODERESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_SetPublishingModeResponse_copy(const UA_SetPublishingModeResponse *src, UA_SetPublishingModeResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SETPUBLISHINGMODERESPONSE]);
}

static UA_INLINE void
UA_SetPublishingModeResponse_deleteMembers(UA_SetPublishingModeResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SETPUBLISHINGMODERESPONSE]);
}

static UA_INLINE void
UA_SetPublishingModeResponse_delete(UA_SetPublishingModeResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SETPUBLISHINGMODERESPONSE]);
}

/* ContentFilterResult */
static UA_INLINE void
UA_ContentFilterResult_init(UA_ContentFilterResult *p) {
    memset(p, 0, sizeof(UA_ContentFilterResult));
}

static UA_INLINE UA_ContentFilterResult *
UA_ContentFilterResult_new(void) {
    return (UA_ContentFilterResult*)UA_new(&UA_TYPES[UA_TYPES_CONTENTFILTERRESULT]);
}

static UA_INLINE UA_StatusCode
UA_ContentFilterResult_copy(const UA_ContentFilterResult *src, UA_ContentFilterResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CONTENTFILTERRESULT]);
}

static UA_INLINE void
UA_ContentFilterResult_deleteMembers(UA_ContentFilterResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CONTENTFILTERRESULT]);
}

static UA_INLINE void
UA_ContentFilterResult_delete(UA_ContentFilterResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CONTENTFILTERRESULT]);
}

/* RegisterServerResponse */
static UA_INLINE void
UA_RegisterServerResponse_init(UA_RegisterServerResponse *p) {
    memset(p, 0, sizeof(UA_RegisterServerResponse));
}

static UA_INLINE UA_RegisterServerResponse *
UA_RegisterServerResponse_new(void) {
    return (UA_RegisterServerResponse*)UA_new(&UA_TYPES[UA_TYPES_REGISTERSERVERRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_RegisterServerResponse_copy(const UA_RegisterServerResponse *src, UA_RegisterServerResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REGISTERSERVERRESPONSE]);
}

static UA_INLINE void
UA_RegisterServerResponse_deleteMembers(UA_RegisterServerResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REGISTERSERVERRESPONSE]);
}

static UA_INLINE void
UA_RegisterServerResponse_delete(UA_RegisterServerResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REGISTERSERVERRESPONSE]);
}

/* AddReferencesItem */
static UA_INLINE void
UA_AddReferencesItem_init(UA_AddReferencesItem *p) {
    memset(p, 0, sizeof(UA_AddReferencesItem));
}

static UA_INLINE UA_AddReferencesItem *
UA_AddReferencesItem_new(void) {
    return (UA_AddReferencesItem*)UA_new(&UA_TYPES[UA_TYPES_ADDREFERENCESITEM]);
}

static UA_INLINE UA_StatusCode
UA_AddReferencesItem_copy(const UA_AddReferencesItem *src, UA_AddReferencesItem *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ADDREFERENCESITEM]);
}

static UA_INLINE void
UA_AddReferencesItem_deleteMembers(UA_AddReferencesItem *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ADDREFERENCESITEM]);
}

static UA_INLINE void
UA_AddReferencesItem_delete(UA_AddReferencesItem *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ADDREFERENCESITEM]);
}

/* QueryDataDescription */
static UA_INLINE void
UA_QueryDataDescription_init(UA_QueryDataDescription *p) {
    memset(p, 0, sizeof(UA_QueryDataDescription));
}

static UA_INLINE UA_QueryDataDescription *
UA_QueryDataDescription_new(void) {
    return (UA_QueryDataDescription*)UA_new(&UA_TYPES[UA_TYPES_QUERYDATADESCRIPTION]);
}

static UA_INLINE UA_StatusCode
UA_QueryDataDescription_copy(const UA_QueryDataDescription *src, UA_QueryDataDescription *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_QUERYDATADESCRIPTION]);
}

static UA_INLINE void
UA_QueryDataDescription_deleteMembers(UA_QueryDataDescription *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_QUERYDATADESCRIPTION]);
}

static UA_INLINE void
UA_QueryDataDescription_delete(UA_QueryDataDescription *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_QUERYDATADESCRIPTION]);
}

/* CreateSubscriptionResponse */
static UA_INLINE void
UA_CreateSubscriptionResponse_init(UA_CreateSubscriptionResponse *p) {
    memset(p, 0, sizeof(UA_CreateSubscriptionResponse));
}

static UA_INLINE UA_CreateSubscriptionResponse *
UA_CreateSubscriptionResponse_new(void) {
    return (UA_CreateSubscriptionResponse*)UA_new(&UA_TYPES[UA_TYPES_CREATESUBSCRIPTIONRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_CreateSubscriptionResponse_copy(const UA_CreateSubscriptionResponse *src, UA_CreateSubscriptionResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CREATESUBSCRIPTIONRESPONSE]);
}

static UA_INLINE void
UA_CreateSubscriptionResponse_deleteMembers(UA_CreateSubscriptionResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CREATESUBSCRIPTIONRESPONSE]);
}

static UA_INLINE void
UA_CreateSubscriptionResponse_delete(UA_CreateSubscriptionResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CREATESUBSCRIPTIONRESPONSE]);
}

/* NetworkGroupDataType */
static UA_INLINE void
UA_NetworkGroupDataType_init(UA_NetworkGroupDataType *p) {
    memset(p, 0, sizeof(UA_NetworkGroupDataType));
}

static UA_INLINE UA_NetworkGroupDataType *
UA_NetworkGroupDataType_new(void) {
    return (UA_NetworkGroupDataType*)UA_new(&UA_TYPES[UA_TYPES_NETWORKGROUPDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_NetworkGroupDataType_copy(const UA_NetworkGroupDataType *src, UA_NetworkGroupDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_NETWORKGROUPDATATYPE]);
}

static UA_INLINE void
UA_NetworkGroupDataType_deleteMembers(UA_NetworkGroupDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_NETWORKGROUPDATATYPE]);
}

static UA_INLINE void
UA_NetworkGroupDataType_delete(UA_NetworkGroupDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_NETWORKGROUPDATATYPE]);
}

/* DeleteReferencesResponse */
static UA_INLINE void
UA_DeleteReferencesResponse_init(UA_DeleteReferencesResponse *p) {
    memset(p, 0, sizeof(UA_DeleteReferencesResponse));
}

static UA_INLINE UA_DeleteReferencesResponse *
UA_DeleteReferencesResponse_new(void) {
    return (UA_DeleteReferencesResponse*)UA_new(&UA_TYPES[UA_TYPES_DELETEREFERENCESRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_DeleteReferencesResponse_copy(const UA_DeleteReferencesResponse *src, UA_DeleteReferencesResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETEREFERENCESRESPONSE]);
}

static UA_INLINE void
UA_DeleteReferencesResponse_deleteMembers(UA_DeleteReferencesResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETEREFERENCESRESPONSE]);
}

static UA_INLINE void
UA_DeleteReferencesResponse_delete(UA_DeleteReferencesResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETEREFERENCESRESPONSE]);
}

/* CreateMonitoredItemsResponse */
static UA_INLINE void
UA_CreateMonitoredItemsResponse_init(UA_CreateMonitoredItemsResponse *p) {
    memset(p, 0, sizeof(UA_CreateMonitoredItemsResponse));
}

static UA_INLINE UA_CreateMonitoredItemsResponse *
UA_CreateMonitoredItemsResponse_new(void) {
    return (UA_CreateMonitoredItemsResponse*)UA_new(&UA_TYPES[UA_TYPES_CREATEMONITOREDITEMSRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_CreateMonitoredItemsResponse_copy(const UA_CreateMonitoredItemsResponse *src, UA_CreateMonitoredItemsResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CREATEMONITOREDITEMSRESPONSE]);
}

static UA_INLINE void
UA_CreateMonitoredItemsResponse_deleteMembers(UA_CreateMonitoredItemsResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CREATEMONITOREDITEMSRESPONSE]);
}

static UA_INLINE void
UA_CreateMonitoredItemsResponse_delete(UA_CreateMonitoredItemsResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CREATEMONITOREDITEMSRESPONSE]);
}

/* CallResponse */
static UA_INLINE void
UA_CallResponse_init(UA_CallResponse *p) {
    memset(p, 0, sizeof(UA_CallResponse));
}

static UA_INLINE UA_CallResponse *
UA_CallResponse_new(void) {
    return (UA_CallResponse*)UA_new(&UA_TYPES[UA_TYPES_CALLRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_CallResponse_copy(const UA_CallResponse *src, UA_CallResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CALLRESPONSE]);
}

static UA_INLINE void
UA_CallResponse_deleteMembers(UA_CallResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CALLRESPONSE]);
}

static UA_INLINE void
UA_CallResponse_delete(UA_CallResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CALLRESPONSE]);
}

/* DeleteNodesResponse */
static UA_INLINE void
UA_DeleteNodesResponse_init(UA_DeleteNodesResponse *p) {
    memset(p, 0, sizeof(UA_DeleteNodesResponse));
}

static UA_INLINE UA_DeleteNodesResponse *
UA_DeleteNodesResponse_new(void) {
    return (UA_DeleteNodesResponse*)UA_new(&UA_TYPES[UA_TYPES_DELETENODESRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_DeleteNodesResponse_copy(const UA_DeleteNodesResponse *src, UA_DeleteNodesResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETENODESRESPONSE]);
}

static UA_INLINE void
UA_DeleteNodesResponse_deleteMembers(UA_DeleteNodesResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETENODESRESPONSE]);
}

static UA_INLINE void
UA_DeleteNodesResponse_delete(UA_DeleteNodesResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETENODESRESPONSE]);
}

/* RepublishResponse */
static UA_INLINE void
UA_RepublishResponse_init(UA_RepublishResponse *p) {
    memset(p, 0, sizeof(UA_RepublishResponse));
}

static UA_INLINE UA_RepublishResponse *
UA_RepublishResponse_new(void) {
    return (UA_RepublishResponse*)UA_new(&UA_TYPES[UA_TYPES_REPUBLISHRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_RepublishResponse_copy(const UA_RepublishResponse *src, UA_RepublishResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REPUBLISHRESPONSE]);
}

static UA_INLINE void
UA_RepublishResponse_deleteMembers(UA_RepublishResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REPUBLISHRESPONSE]);
}

static UA_INLINE void
UA_RepublishResponse_delete(UA_RepublishResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REPUBLISHRESPONSE]);
}

/* MonitoredItemCreateRequest */
static UA_INLINE void
UA_MonitoredItemCreateRequest_init(UA_MonitoredItemCreateRequest *p) {
    memset(p, 0, sizeof(UA_MonitoredItemCreateRequest));
}

static UA_INLINE UA_MonitoredItemCreateRequest *
UA_MonitoredItemCreateRequest_new(void) {
    return (UA_MonitoredItemCreateRequest*)UA_new(&UA_TYPES[UA_TYPES_MONITOREDITEMCREATEREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_MonitoredItemCreateRequest_copy(const UA_MonitoredItemCreateRequest *src, UA_MonitoredItemCreateRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_MONITOREDITEMCREATEREQUEST]);
}

static UA_INLINE void
UA_MonitoredItemCreateRequest_deleteMembers(UA_MonitoredItemCreateRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_MONITOREDITEMCREATEREQUEST]);
}

static UA_INLINE void
UA_MonitoredItemCreateRequest_delete(UA_MonitoredItemCreateRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_MONITOREDITEMCREATEREQUEST]);
}

/* DeleteReferencesRequest */
static UA_INLINE void
UA_DeleteReferencesRequest_init(UA_DeleteReferencesRequest *p) {
    memset(p, 0, sizeof(UA_DeleteReferencesRequest));
}

static UA_INLINE UA_DeleteReferencesRequest *
UA_DeleteReferencesRequest_new(void) {
    return (UA_DeleteReferencesRequest*)UA_new(&UA_TYPES[UA_TYPES_DELETEREFERENCESREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_DeleteReferencesRequest_copy(const UA_DeleteReferencesRequest *src, UA_DeleteReferencesRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_DELETEREFERENCESREQUEST]);
}

static UA_INLINE void
UA_DeleteReferencesRequest_deleteMembers(UA_DeleteReferencesRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_DELETEREFERENCESREQUEST]);
}

static UA_INLINE void
UA_DeleteReferencesRequest_delete(UA_DeleteReferencesRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DELETEREFERENCESREQUEST]);
}

/* ReadResponse */
static UA_INLINE void
UA_ReadResponse_init(UA_ReadResponse *p) {
    memset(p, 0, sizeof(UA_ReadResponse));
}

static UA_INLINE UA_ReadResponse *
UA_ReadResponse_new(void) {
    return (UA_ReadResponse*)UA_new(&UA_TYPES[UA_TYPES_READRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_ReadResponse_copy(const UA_ReadResponse *src, UA_ReadResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_READRESPONSE]);
}

static UA_INLINE void
UA_ReadResponse_deleteMembers(UA_ReadResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_READRESPONSE]);
}

static UA_INLINE void
UA_ReadResponse_delete(UA_ReadResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_READRESPONSE]);
}

/* AddReferencesRequest */
static UA_INLINE void
UA_AddReferencesRequest_init(UA_AddReferencesRequest *p) {
    memset(p, 0, sizeof(UA_AddReferencesRequest));
}

static UA_INLINE UA_AddReferencesRequest *
UA_AddReferencesRequest_new(void) {
    return (UA_AddReferencesRequest*)UA_new(&UA_TYPES[UA_TYPES_ADDREFERENCESREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_AddReferencesRequest_copy(const UA_AddReferencesRequest *src, UA_AddReferencesRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ADDREFERENCESREQUEST]);
}

static UA_INLINE void
UA_AddReferencesRequest_deleteMembers(UA_AddReferencesRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ADDREFERENCESREQUEST]);
}

static UA_INLINE void
UA_AddReferencesRequest_delete(UA_AddReferencesRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ADDREFERENCESREQUEST]);
}

/* ReadRequest */
static UA_INLINE void
UA_ReadRequest_init(UA_ReadRequest *p) {
    memset(p, 0, sizeof(UA_ReadRequest));
}

static UA_INLINE UA_ReadRequest *
UA_ReadRequest_new(void) {
    return (UA_ReadRequest*)UA_new(&UA_TYPES[UA_TYPES_READREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_ReadRequest_copy(const UA_ReadRequest *src, UA_ReadRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_READREQUEST]);
}

static UA_INLINE void
UA_ReadRequest_deleteMembers(UA_ReadRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_READREQUEST]);
}

static UA_INLINE void
UA_ReadRequest_delete(UA_ReadRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_READREQUEST]);
}

/* OpenSecureChannelRequest */
static UA_INLINE void
UA_OpenSecureChannelRequest_init(UA_OpenSecureChannelRequest *p) {
    memset(p, 0, sizeof(UA_OpenSecureChannelRequest));
}

static UA_INLINE UA_OpenSecureChannelRequest *
UA_OpenSecureChannelRequest_new(void) {
    return (UA_OpenSecureChannelRequest*)UA_new(&UA_TYPES[UA_TYPES_OPENSECURECHANNELREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_OpenSecureChannelRequest_copy(const UA_OpenSecureChannelRequest *src, UA_OpenSecureChannelRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_OPENSECURECHANNELREQUEST]);
}

static UA_INLINE void
UA_OpenSecureChannelRequest_deleteMembers(UA_OpenSecureChannelRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_OPENSECURECHANNELREQUEST]);
}

static UA_INLINE void
UA_OpenSecureChannelRequest_delete(UA_OpenSecureChannelRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_OPENSECURECHANNELREQUEST]);
}

/* RegisterServer2Response */
static UA_INLINE void
UA_RegisterServer2Response_init(UA_RegisterServer2Response *p) {
    memset(p, 0, sizeof(UA_RegisterServer2Response));
}

static UA_INLINE UA_RegisterServer2Response *
UA_RegisterServer2Response_new(void) {
    return (UA_RegisterServer2Response*)UA_new(&UA_TYPES[UA_TYPES_REGISTERSERVER2RESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_RegisterServer2Response_copy(const UA_RegisterServer2Response *src, UA_RegisterServer2Response *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REGISTERSERVER2RESPONSE]);
}

static UA_INLINE void
UA_RegisterServer2Response_deleteMembers(UA_RegisterServer2Response *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REGISTERSERVER2RESPONSE]);
}

static UA_INLINE void
UA_RegisterServer2Response_delete(UA_RegisterServer2Response *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REGISTERSERVER2RESPONSE]);
}

/* AddNodesItem */
static UA_INLINE void
UA_AddNodesItem_init(UA_AddNodesItem *p) {
    memset(p, 0, sizeof(UA_AddNodesItem));
}

static UA_INLINE UA_AddNodesItem *
UA_AddNodesItem_new(void) {
    return (UA_AddNodesItem*)UA_new(&UA_TYPES[UA_TYPES_ADDNODESITEM]);
}

static UA_INLINE UA_StatusCode
UA_AddNodesItem_copy(const UA_AddNodesItem *src, UA_AddNodesItem *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ADDNODESITEM]);
}

static UA_INLINE void
UA_AddNodesItem_deleteMembers(UA_AddNodesItem *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ADDNODESITEM]);
}

static UA_INLINE void
UA_AddNodesItem_delete(UA_AddNodesItem *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ADDNODESITEM]);
}

/* NodeTypeDescription */
static UA_INLINE void
UA_NodeTypeDescription_init(UA_NodeTypeDescription *p) {
    memset(p, 0, sizeof(UA_NodeTypeDescription));
}

static UA_INLINE UA_NodeTypeDescription *
UA_NodeTypeDescription_new(void) {
    return (UA_NodeTypeDescription*)UA_new(&UA_TYPES[UA_TYPES_NODETYPEDESCRIPTION]);
}

static UA_INLINE UA_StatusCode
UA_NodeTypeDescription_copy(const UA_NodeTypeDescription *src, UA_NodeTypeDescription *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_NODETYPEDESCRIPTION]);
}

static UA_INLINE void
UA_NodeTypeDescription_deleteMembers(UA_NodeTypeDescription *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_NODETYPEDESCRIPTION]);
}

static UA_INLINE void
UA_NodeTypeDescription_delete(UA_NodeTypeDescription *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_NODETYPEDESCRIPTION]);
}

/* ServerStatusDataType */
static UA_INLINE void
UA_ServerStatusDataType_init(UA_ServerStatusDataType *p) {
    memset(p, 0, sizeof(UA_ServerStatusDataType));
}

static UA_INLINE UA_ServerStatusDataType *
UA_ServerStatusDataType_new(void) {
    return (UA_ServerStatusDataType*)UA_new(&UA_TYPES[UA_TYPES_SERVERSTATUSDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_ServerStatusDataType_copy(const UA_ServerStatusDataType *src, UA_ServerStatusDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SERVERSTATUSDATATYPE]);
}

static UA_INLINE void
UA_ServerStatusDataType_deleteMembers(UA_ServerStatusDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SERVERSTATUSDATATYPE]);
}

static UA_INLINE void
UA_ServerStatusDataType_delete(UA_ServerStatusDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SERVERSTATUSDATATYPE]);
}

/* AttributeOperand */
static UA_INLINE void
UA_AttributeOperand_init(UA_AttributeOperand *p) {
    memset(p, 0, sizeof(UA_AttributeOperand));
}

static UA_INLINE UA_AttributeOperand *
UA_AttributeOperand_new(void) {
    return (UA_AttributeOperand*)UA_new(&UA_TYPES[UA_TYPES_ATTRIBUTEOPERAND]);
}

static UA_INLINE UA_StatusCode
UA_AttributeOperand_copy(const UA_AttributeOperand *src, UA_AttributeOperand *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ATTRIBUTEOPERAND]);
}

static UA_INLINE void
UA_AttributeOperand_deleteMembers(UA_AttributeOperand *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ATTRIBUTEOPERAND]);
}

static UA_INLINE void
UA_AttributeOperand_delete(UA_AttributeOperand *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ATTRIBUTEOPERAND]);
}

/* AddReferencesResponse */
static UA_INLINE void
UA_AddReferencesResponse_init(UA_AddReferencesResponse *p) {
    memset(p, 0, sizeof(UA_AddReferencesResponse));
}

static UA_INLINE UA_AddReferencesResponse *
UA_AddReferencesResponse_new(void) {
    return (UA_AddReferencesResponse*)UA_new(&UA_TYPES[UA_TYPES_ADDREFERENCESRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_AddReferencesResponse_copy(const UA_AddReferencesResponse *src, UA_AddReferencesResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ADDREFERENCESRESPONSE]);
}

static UA_INLINE void
UA_AddReferencesResponse_deleteMembers(UA_AddReferencesResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ADDREFERENCESRESPONSE]);
}

static UA_INLINE void
UA_AddReferencesResponse_delete(UA_AddReferencesResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ADDREFERENCESRESPONSE]);
}

/* EventFilterResult */
static UA_INLINE void
UA_EventFilterResult_init(UA_EventFilterResult *p) {
    memset(p, 0, sizeof(UA_EventFilterResult));
}

static UA_INLINE UA_EventFilterResult *
UA_EventFilterResult_new(void) {
    return (UA_EventFilterResult*)UA_new(&UA_TYPES[UA_TYPES_EVENTFILTERRESULT]);
}

static UA_INLINE UA_StatusCode
UA_EventFilterResult_copy(const UA_EventFilterResult *src, UA_EventFilterResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_EVENTFILTERRESULT]);
}

static UA_INLINE void
UA_EventFilterResult_deleteMembers(UA_EventFilterResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_EVENTFILTERRESULT]);
}

static UA_INLINE void
UA_EventFilterResult_delete(UA_EventFilterResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_EVENTFILTERRESULT]);
}

/* TranslateBrowsePathsToNodeIdsResponse */
static UA_INLINE void
UA_TranslateBrowsePathsToNodeIdsResponse_init(UA_TranslateBrowsePathsToNodeIdsResponse *p) {
    memset(p, 0, sizeof(UA_TranslateBrowsePathsToNodeIdsResponse));
}

static UA_INLINE UA_TranslateBrowsePathsToNodeIdsResponse *
UA_TranslateBrowsePathsToNodeIdsResponse_new(void) {
    return (UA_TranslateBrowsePathsToNodeIdsResponse*)UA_new(&UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_TranslateBrowsePathsToNodeIdsResponse_copy(const UA_TranslateBrowsePathsToNodeIdsResponse *src, UA_TranslateBrowsePathsToNodeIdsResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE]);
}

static UA_INLINE void
UA_TranslateBrowsePathsToNodeIdsResponse_deleteMembers(UA_TranslateBrowsePathsToNodeIdsResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE]);
}

static UA_INLINE void
UA_TranslateBrowsePathsToNodeIdsResponse_delete(UA_TranslateBrowsePathsToNodeIdsResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE]);
}

/* DataChangeFilter */
static UA_INLINE void
UA_DataChangeFilter_init(UA_DataChangeFilter *p) {
    memset(p, 0, sizeof(UA_DataChangeFilter));
}

static UA_INLINE UA_DataChangeFilter *
UA_DataChangeFilter_new(void) {
    return (UA_DataChangeFilter*)UA_new(&UA_TYPES[UA_TYPES_DATACHANGEFILTER]);
}

static UA_INLINE UA_StatusCode
UA_DataChangeFilter_copy(const UA_DataChangeFilter *src, UA_DataChangeFilter *dst) {
    *dst = *src;
    return UA_STATUSCODE_GOOD;
}

static UA_INLINE void
UA_DataChangeFilter_deleteMembers(UA_DataChangeFilter *p) { }

static UA_INLINE void
UA_DataChangeFilter_delete(UA_DataChangeFilter *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_DATACHANGEFILTER]);
}

/* ContentFilterElement */
static UA_INLINE void
UA_ContentFilterElement_init(UA_ContentFilterElement *p) {
    memset(p, 0, sizeof(UA_ContentFilterElement));
}

static UA_INLINE UA_ContentFilterElement *
UA_ContentFilterElement_new(void) {
    return (UA_ContentFilterElement*)UA_new(&UA_TYPES[UA_TYPES_CONTENTFILTERELEMENT]);
}

static UA_INLINE UA_StatusCode
UA_ContentFilterElement_copy(const UA_ContentFilterElement *src, UA_ContentFilterElement *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENT]);
}

static UA_INLINE void
UA_ContentFilterElement_deleteMembers(UA_ContentFilterElement *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENT]);
}

static UA_INLINE void
UA_ContentFilterElement_delete(UA_ContentFilterElement *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CONTENTFILTERELEMENT]);
}

/* TranslateBrowsePathsToNodeIdsRequest */
static UA_INLINE void
UA_TranslateBrowsePathsToNodeIdsRequest_init(UA_TranslateBrowsePathsToNodeIdsRequest *p) {
    memset(p, 0, sizeof(UA_TranslateBrowsePathsToNodeIdsRequest));
}

static UA_INLINE UA_TranslateBrowsePathsToNodeIdsRequest *
UA_TranslateBrowsePathsToNodeIdsRequest_new(void) {
    return (UA_TranslateBrowsePathsToNodeIdsRequest*)UA_new(&UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_TranslateBrowsePathsToNodeIdsRequest_copy(const UA_TranslateBrowsePathsToNodeIdsRequest *src, UA_TranslateBrowsePathsToNodeIdsRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSREQUEST]);
}

static UA_INLINE void
UA_TranslateBrowsePathsToNodeIdsRequest_deleteMembers(UA_TranslateBrowsePathsToNodeIdsRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSREQUEST]);
}

static UA_INLINE void
UA_TranslateBrowsePathsToNodeIdsRequest_delete(UA_TranslateBrowsePathsToNodeIdsRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSREQUEST]);
}

/* CloseSessionResponse */
static UA_INLINE void
UA_CloseSessionResponse_init(UA_CloseSessionResponse *p) {
    memset(p, 0, sizeof(UA_CloseSessionResponse));
}

static UA_INLINE UA_CloseSessionResponse *
UA_CloseSessionResponse_new(void) {
    return (UA_CloseSessionResponse*)UA_new(&UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_CloseSessionResponse_copy(const UA_CloseSessionResponse *src, UA_CloseSessionResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE]);
}

static UA_INLINE void
UA_CloseSessionResponse_deleteMembers(UA_CloseSessionResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE]);
}

static UA_INLINE void
UA_CloseSessionResponse_delete(UA_CloseSessionResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE]);
}

/* ApplicationDescription */
static UA_INLINE void
UA_ApplicationDescription_init(UA_ApplicationDescription *p) {
    memset(p, 0, sizeof(UA_ApplicationDescription));
}

static UA_INLINE UA_ApplicationDescription *
UA_ApplicationDescription_new(void) {
    return (UA_ApplicationDescription*)UA_new(&UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
}

static UA_INLINE UA_StatusCode
UA_ApplicationDescription_copy(const UA_ApplicationDescription *src, UA_ApplicationDescription *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
}

static UA_INLINE void
UA_ApplicationDescription_deleteMembers(UA_ApplicationDescription *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
}

static UA_INLINE void
UA_ApplicationDescription_delete(UA_ApplicationDescription *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
}

/* SessionDiagnosticsDataType */
static UA_INLINE void
UA_SessionDiagnosticsDataType_init(UA_SessionDiagnosticsDataType *p) {
    memset(p, 0, sizeof(UA_SessionDiagnosticsDataType));
}

static UA_INLINE UA_SessionDiagnosticsDataType *
UA_SessionDiagnosticsDataType_new(void) {
    return (UA_SessionDiagnosticsDataType*)UA_new(&UA_TYPES[UA_TYPES_SESSIONDIAGNOSTICSDATATYPE]);
}

static UA_INLINE UA_StatusCode
UA_SessionDiagnosticsDataType_copy(const UA_SessionDiagnosticsDataType *src, UA_SessionDiagnosticsDataType *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SESSIONDIAGNOSTICSDATATYPE]);
}

static UA_INLINE void
UA_SessionDiagnosticsDataType_deleteMembers(UA_SessionDiagnosticsDataType *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SESSIONDIAGNOSTICSDATATYPE]);
}

static UA_INLINE void
UA_SessionDiagnosticsDataType_delete(UA_SessionDiagnosticsDataType *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SESSIONDIAGNOSTICSDATATYPE]);
}

/* ServiceFault */
static UA_INLINE void
UA_ServiceFault_init(UA_ServiceFault *p) {
    memset(p, 0, sizeof(UA_ServiceFault));
}

static UA_INLINE UA_ServiceFault *
UA_ServiceFault_new(void) {
    return (UA_ServiceFault*)UA_new(&UA_TYPES[UA_TYPES_SERVICEFAULT]);
}

static UA_INLINE UA_StatusCode
UA_ServiceFault_copy(const UA_ServiceFault *src, UA_ServiceFault *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_SERVICEFAULT]);
}

static UA_INLINE void
UA_ServiceFault_deleteMembers(UA_ServiceFault *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_SERVICEFAULT]);
}

static UA_INLINE void
UA_ServiceFault_delete(UA_ServiceFault *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_SERVICEFAULT]);
}

/* RegisteredServer */
static UA_INLINE void
UA_RegisteredServer_init(UA_RegisteredServer *p) {
    memset(p, 0, sizeof(UA_RegisteredServer));
}

static UA_INLINE UA_RegisteredServer *
UA_RegisteredServer_new(void) {
    return (UA_RegisteredServer*)UA_new(&UA_TYPES[UA_TYPES_REGISTEREDSERVER]);
}

static UA_INLINE UA_StatusCode
UA_RegisteredServer_copy(const UA_RegisteredServer *src, UA_RegisteredServer *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REGISTEREDSERVER]);
}

static UA_INLINE void
UA_RegisteredServer_deleteMembers(UA_RegisteredServer *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REGISTEREDSERVER]);
}

static UA_INLINE void
UA_RegisteredServer_delete(UA_RegisteredServer *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REGISTEREDSERVER]);
}

/* AggregateFilter */
static UA_INLINE void
UA_AggregateFilter_init(UA_AggregateFilter *p) {
    memset(p, 0, sizeof(UA_AggregateFilter));
}

static UA_INLINE UA_AggregateFilter *
UA_AggregateFilter_new(void) {
    return (UA_AggregateFilter*)UA_new(&UA_TYPES[UA_TYPES_AGGREGATEFILTER]);
}

static UA_INLINE UA_StatusCode
UA_AggregateFilter_copy(const UA_AggregateFilter *src, UA_AggregateFilter *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_AGGREGATEFILTER]);
}

static UA_INLINE void
UA_AggregateFilter_deleteMembers(UA_AggregateFilter *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_AGGREGATEFILTER]);
}

static UA_INLINE void
UA_AggregateFilter_delete(UA_AggregateFilter *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_AGGREGATEFILTER]);
}

/* RegisterServerRequest */
static UA_INLINE void
UA_RegisterServerRequest_init(UA_RegisterServerRequest *p) {
    memset(p, 0, sizeof(UA_RegisterServerRequest));
}

static UA_INLINE UA_RegisterServerRequest *
UA_RegisterServerRequest_new(void) {
    return (UA_RegisterServerRequest*)UA_new(&UA_TYPES[UA_TYPES_REGISTERSERVERREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_RegisterServerRequest_copy(const UA_RegisterServerRequest *src, UA_RegisterServerRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REGISTERSERVERREQUEST]);
}

static UA_INLINE void
UA_RegisterServerRequest_deleteMembers(UA_RegisterServerRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REGISTERSERVERREQUEST]);
}

static UA_INLINE void
UA_RegisterServerRequest_delete(UA_RegisterServerRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REGISTERSERVERREQUEST]);
}

/* EndpointDescription */
static UA_INLINE void
UA_EndpointDescription_init(UA_EndpointDescription *p) {
    memset(p, 0, sizeof(UA_EndpointDescription));
}

static UA_INLINE UA_EndpointDescription *
UA_EndpointDescription_new(void) {
    return (UA_EndpointDescription*)UA_new(&UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
}

static UA_INLINE UA_StatusCode
UA_EndpointDescription_copy(const UA_EndpointDescription *src, UA_EndpointDescription *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
}

static UA_INLINE void
UA_EndpointDescription_deleteMembers(UA_EndpointDescription *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
}

static UA_INLINE void
UA_EndpointDescription_delete(UA_EndpointDescription *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
}

/* CreateMonitoredItemsRequest */
static UA_INLINE void
UA_CreateMonitoredItemsRequest_init(UA_CreateMonitoredItemsRequest *p) {
    memset(p, 0, sizeof(UA_CreateMonitoredItemsRequest));
}

static UA_INLINE UA_CreateMonitoredItemsRequest *
UA_CreateMonitoredItemsRequest_new(void) {
    return (UA_CreateMonitoredItemsRequest*)UA_new(&UA_TYPES[UA_TYPES_CREATEMONITOREDITEMSREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_CreateMonitoredItemsRequest_copy(const UA_CreateMonitoredItemsRequest *src, UA_CreateMonitoredItemsRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CREATEMONITOREDITEMSREQUEST]);
}

static UA_INLINE void
UA_CreateMonitoredItemsRequest_deleteMembers(UA_CreateMonitoredItemsRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CREATEMONITOREDITEMSREQUEST]);
}

static UA_INLINE void
UA_CreateMonitoredItemsRequest_delete(UA_CreateMonitoredItemsRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CREATEMONITOREDITEMSREQUEST]);
}

/* ContentFilter */
static UA_INLINE void
UA_ContentFilter_init(UA_ContentFilter *p) {
    memset(p, 0, sizeof(UA_ContentFilter));
}

static UA_INLINE UA_ContentFilter *
UA_ContentFilter_new(void) {
    return (UA_ContentFilter*)UA_new(&UA_TYPES[UA_TYPES_CONTENTFILTER]);
}

static UA_INLINE UA_StatusCode
UA_ContentFilter_copy(const UA_ContentFilter *src, UA_ContentFilter *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CONTENTFILTER]);
}

static UA_INLINE void
UA_ContentFilter_deleteMembers(UA_ContentFilter *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CONTENTFILTER]);
}

static UA_INLINE void
UA_ContentFilter_delete(UA_ContentFilter *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CONTENTFILTER]);
}

/* QueryFirstResponse */
static UA_INLINE void
UA_QueryFirstResponse_init(UA_QueryFirstResponse *p) {
    memset(p, 0, sizeof(UA_QueryFirstResponse));
}

static UA_INLINE UA_QueryFirstResponse *
UA_QueryFirstResponse_new(void) {
    return (UA_QueryFirstResponse*)UA_new(&UA_TYPES[UA_TYPES_QUERYFIRSTRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_QueryFirstResponse_copy(const UA_QueryFirstResponse *src, UA_QueryFirstResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_QUERYFIRSTRESPONSE]);
}

static UA_INLINE void
UA_QueryFirstResponse_deleteMembers(UA_QueryFirstResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_QUERYFIRSTRESPONSE]);
}

static UA_INLINE void
UA_QueryFirstResponse_delete(UA_QueryFirstResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_QUERYFIRSTRESPONSE]);
}

/* AddNodesRequest */
static UA_INLINE void
UA_AddNodesRequest_init(UA_AddNodesRequest *p) {
    memset(p, 0, sizeof(UA_AddNodesRequest));
}

static UA_INLINE UA_AddNodesRequest *
UA_AddNodesRequest_new(void) {
    return (UA_AddNodesRequest*)UA_new(&UA_TYPES[UA_TYPES_ADDNODESREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_AddNodesRequest_copy(const UA_AddNodesRequest *src, UA_AddNodesRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_ADDNODESREQUEST]);
}

static UA_INLINE void
UA_AddNodesRequest_deleteMembers(UA_AddNodesRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_ADDNODESREQUEST]);
}

static UA_INLINE void
UA_AddNodesRequest_delete(UA_AddNodesRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_ADDNODESREQUEST]);
}

/* BrowseRequest */
static UA_INLINE void
UA_BrowseRequest_init(UA_BrowseRequest *p) {
    memset(p, 0, sizeof(UA_BrowseRequest));
}

static UA_INLINE UA_BrowseRequest *
UA_BrowseRequest_new(void) {
    return (UA_BrowseRequest*)UA_new(&UA_TYPES[UA_TYPES_BROWSEREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_BrowseRequest_copy(const UA_BrowseRequest *src, UA_BrowseRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSEREQUEST]);
}

static UA_INLINE void
UA_BrowseRequest_deleteMembers(UA_BrowseRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSEREQUEST]);
}

static UA_INLINE void
UA_BrowseRequest_delete(UA_BrowseRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSEREQUEST]);
}

/* BrowseResult */
static UA_INLINE void
UA_BrowseResult_init(UA_BrowseResult *p) {
    memset(p, 0, sizeof(UA_BrowseResult));
}

static UA_INLINE UA_BrowseResult *
UA_BrowseResult_new(void) {
    return (UA_BrowseResult*)UA_new(&UA_TYPES[UA_TYPES_BROWSERESULT]);
}

static UA_INLINE UA_StatusCode
UA_BrowseResult_copy(const UA_BrowseResult *src, UA_BrowseResult *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSERESULT]);
}

static UA_INLINE void
UA_BrowseResult_deleteMembers(UA_BrowseResult *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSERESULT]);
}

static UA_INLINE void
UA_BrowseResult_delete(UA_BrowseResult *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSERESULT]);
}

/* RegisterServer2Request */
static UA_INLINE void
UA_RegisterServer2Request_init(UA_RegisterServer2Request *p) {
    memset(p, 0, sizeof(UA_RegisterServer2Request));
}

static UA_INLINE UA_RegisterServer2Request *
UA_RegisterServer2Request_new(void) {
    return (UA_RegisterServer2Request*)UA_new(&UA_TYPES[UA_TYPES_REGISTERSERVER2REQUEST]);
}

static UA_INLINE UA_StatusCode
UA_RegisterServer2Request_copy(const UA_RegisterServer2Request *src, UA_RegisterServer2Request *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_REGISTERSERVER2REQUEST]);
}

static UA_INLINE void
UA_RegisterServer2Request_deleteMembers(UA_RegisterServer2Request *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_REGISTERSERVER2REQUEST]);
}

static UA_INLINE void
UA_RegisterServer2Request_delete(UA_RegisterServer2Request *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_REGISTERSERVER2REQUEST]);
}

/* CreateSessionRequest */
static UA_INLINE void
UA_CreateSessionRequest_init(UA_CreateSessionRequest *p) {
    memset(p, 0, sizeof(UA_CreateSessionRequest));
}

static UA_INLINE UA_CreateSessionRequest *
UA_CreateSessionRequest_new(void) {
    return (UA_CreateSessionRequest*)UA_new(&UA_TYPES[UA_TYPES_CREATESESSIONREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_CreateSessionRequest_copy(const UA_CreateSessionRequest *src, UA_CreateSessionRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CREATESESSIONREQUEST]);
}

static UA_INLINE void
UA_CreateSessionRequest_deleteMembers(UA_CreateSessionRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CREATESESSIONREQUEST]);
}

static UA_INLINE void
UA_CreateSessionRequest_delete(UA_CreateSessionRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CREATESESSIONREQUEST]);
}

/* EventFilter */
static UA_INLINE void
UA_EventFilter_init(UA_EventFilter *p) {
    memset(p, 0, sizeof(UA_EventFilter));
}

static UA_INLINE UA_EventFilter *
UA_EventFilter_new(void) {
    return (UA_EventFilter*)UA_new(&UA_TYPES[UA_TYPES_EVENTFILTER]);
}

static UA_INLINE UA_StatusCode
UA_EventFilter_copy(const UA_EventFilter *src, UA_EventFilter *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_EVENTFILTER]);
}

static UA_INLINE void
UA_EventFilter_deleteMembers(UA_EventFilter *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_EVENTFILTER]);
}

static UA_INLINE void
UA_EventFilter_delete(UA_EventFilter *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_EVENTFILTER]);
}

/* GetEndpointsResponse */
static UA_INLINE void
UA_GetEndpointsResponse_init(UA_GetEndpointsResponse *p) {
    memset(p, 0, sizeof(UA_GetEndpointsResponse));
}

static UA_INLINE UA_GetEndpointsResponse *
UA_GetEndpointsResponse_new(void) {
    return (UA_GetEndpointsResponse*)UA_new(&UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_GetEndpointsResponse_copy(const UA_GetEndpointsResponse *src, UA_GetEndpointsResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE]);
}

static UA_INLINE void
UA_GetEndpointsResponse_deleteMembers(UA_GetEndpointsResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE]);
}

static UA_INLINE void
UA_GetEndpointsResponse_delete(UA_GetEndpointsResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE]);
}

/* FindServersResponse */
static UA_INLINE void
UA_FindServersResponse_init(UA_FindServersResponse *p) {
    memset(p, 0, sizeof(UA_FindServersResponse));
}

static UA_INLINE UA_FindServersResponse *
UA_FindServersResponse_new(void) {
    return (UA_FindServersResponse*)UA_new(&UA_TYPES[UA_TYPES_FINDSERVERSRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_FindServersResponse_copy(const UA_FindServersResponse *src, UA_FindServersResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_FINDSERVERSRESPONSE]);
}

static UA_INLINE void
UA_FindServersResponse_deleteMembers(UA_FindServersResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_FINDSERVERSRESPONSE]);
}

static UA_INLINE void
UA_FindServersResponse_delete(UA_FindServersResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_FINDSERVERSRESPONSE]);
}

/* BrowseNextResponse */
static UA_INLINE void
UA_BrowseNextResponse_init(UA_BrowseNextResponse *p) {
    memset(p, 0, sizeof(UA_BrowseNextResponse));
}

static UA_INLINE UA_BrowseNextResponse *
UA_BrowseNextResponse_new(void) {
    return (UA_BrowseNextResponse*)UA_new(&UA_TYPES[UA_TYPES_BROWSENEXTRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_BrowseNextResponse_copy(const UA_BrowseNextResponse *src, UA_BrowseNextResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSENEXTRESPONSE]);
}

static UA_INLINE void
UA_BrowseNextResponse_deleteMembers(UA_BrowseNextResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSENEXTRESPONSE]);
}

static UA_INLINE void
UA_BrowseNextResponse_delete(UA_BrowseNextResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSENEXTRESPONSE]);
}

/* BrowseResponse */
static UA_INLINE void
UA_BrowseResponse_init(UA_BrowseResponse *p) {
    memset(p, 0, sizeof(UA_BrowseResponse));
}

static UA_INLINE UA_BrowseResponse *
UA_BrowseResponse_new(void) {
    return (UA_BrowseResponse*)UA_new(&UA_TYPES[UA_TYPES_BROWSERESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_BrowseResponse_copy(const UA_BrowseResponse *src, UA_BrowseResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_BROWSERESPONSE]);
}

static UA_INLINE void
UA_BrowseResponse_deleteMembers(UA_BrowseResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_BROWSERESPONSE]);
}

static UA_INLINE void
UA_BrowseResponse_delete(UA_BrowseResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_BROWSERESPONSE]);
}

/* CreateSessionResponse */
static UA_INLINE void
UA_CreateSessionResponse_init(UA_CreateSessionResponse *p) {
    memset(p, 0, sizeof(UA_CreateSessionResponse));
}

static UA_INLINE UA_CreateSessionResponse *
UA_CreateSessionResponse_new(void) {
    return (UA_CreateSessionResponse*)UA_new(&UA_TYPES[UA_TYPES_CREATESESSIONRESPONSE]);
}

static UA_INLINE UA_StatusCode
UA_CreateSessionResponse_copy(const UA_CreateSessionResponse *src, UA_CreateSessionResponse *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_CREATESESSIONRESPONSE]);
}

static UA_INLINE void
UA_CreateSessionResponse_deleteMembers(UA_CreateSessionResponse *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_CREATESESSIONRESPONSE]);
}

static UA_INLINE void
UA_CreateSessionResponse_delete(UA_CreateSessionResponse *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_CREATESESSIONRESPONSE]);
}

/* QueryFirstRequest */
static UA_INLINE void
UA_QueryFirstRequest_init(UA_QueryFirstRequest *p) {
    memset(p, 0, sizeof(UA_QueryFirstRequest));
}

static UA_INLINE UA_QueryFirstRequest *
UA_QueryFirstRequest_new(void) {
    return (UA_QueryFirstRequest*)UA_new(&UA_TYPES[UA_TYPES_QUERYFIRSTREQUEST]);
}

static UA_INLINE UA_StatusCode
UA_QueryFirstRequest_copy(const UA_QueryFirstRequest *src, UA_QueryFirstRequest *dst) {
    return UA_copy(src, dst, &UA_TYPES[UA_TYPES_QUERYFIRSTREQUEST]);
}

static UA_INLINE void
UA_QueryFirstRequest_deleteMembers(UA_QueryFirstRequest *p) {
    UA_deleteMembers(p, &UA_TYPES[UA_TYPES_QUERYFIRSTREQUEST]);
}

static UA_INLINE void
UA_QueryFirstRequest_delete(UA_QueryFirstRequest *p) {
    UA_delete(p, &UA_TYPES[UA_TYPES_QUERYFIRSTREQUEST]);
}

#if defined(__GNUC__) && __GNUC__ >= 4 && __GNUC_MINOR__ >= 6
# pragma GCC diagnostic pop
#endif

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_server.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2014-2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2015-2016 (c) Sten Grüner
 *    Copyright 2014-2015, 2017 (c) Florian Palm
 *    Copyright 2015-2016 (c) Chris Iatrou
 *    Copyright 2015-2016 (c) Oleksiy Vasylyev
 *    Copyright 2016-2017 (c) Stefan Profanter, fortiss GmbH
 */


#ifdef __cplusplus
extern "C" {
#endif


struct UA_ServerConfig;
typedef struct UA_ServerConfig UA_ServerConfig;

struct UA_Server;
typedef struct UA_Server UA_Server;

struct UA_ClientConfig;

/**
 * .. _server:
 *
 * Server
 * ======
 *
 * .. include:: server_config.rst
 *
 * .. _server-lifecycle:
 *
 * Server Lifecycle
 * ---------------- */

UA_Server UA_EXPORT * UA_Server_new(const UA_ServerConfig *config);
void UA_EXPORT UA_Server_delete(UA_Server *server);

/* Runs the main loop of the server. In each iteration, this calls into the
 * networklayers to see if messages have arrived.
 *
 * @param server The server object.
 * @param running The loop is run as long as *running is true.
 *        Otherwise, the server shuts down.
 * @return Returns the statuscode of the UA_Server_run_shutdown method */
UA_StatusCode UA_EXPORT
UA_Server_run(UA_Server *server, volatile UA_Boolean *running);

/* The prologue part of UA_Server_run (no need to use if you call
 * UA_Server_run) */
UA_StatusCode UA_EXPORT
UA_Server_run_startup(UA_Server *server);

/* Executes a single iteration of the server's main loop.
 *
 * @param server The server object.
 * @param waitInternal Should we wait for messages in the networklayer?
 *        Otherwise, the timouts for the networklayers are set to zero.
 *        The default max wait time is 50millisec.
 * @return Returns how long we can wait until the next scheduled
 *         callback (in ms) */
UA_UInt16 UA_EXPORT
UA_Server_run_iterate(UA_Server *server, UA_Boolean waitInternal);

/* The epilogue part of UA_Server_run (no need to use if you call
 * UA_Server_run) */
UA_StatusCode UA_EXPORT
UA_Server_run_shutdown(UA_Server *server);

/**
 * Repeated Callbacks
 * ------------------ */
typedef void (*UA_ServerCallback)(UA_Server *server, void *data);

/* Add a callback for cyclic repetition to the server.
 *
 * @param server The server object.
 * @param callback The callback that shall be added.
 * @param interval The callback shall be repeatedly executed with the given interval
 *        (in ms). The interval must be larger than 5ms. The first execution
 *        occurs at now() + interval at the latest.
 * @param callbackId Set to the identifier of the repeated callback . This can be used to cancel
 *        the callback later on. If the pointer is null, the identifier is not set.
 * @return Upon success, UA_STATUSCODE_GOOD is returned.
 *         An error code otherwise. */
UA_StatusCode UA_EXPORT
UA_Server_addRepeatedCallback(UA_Server *server, UA_ServerCallback callback,
                              void *data, UA_UInt32 interval, UA_UInt64 *callbackId);

UA_StatusCode UA_EXPORT
UA_Server_changeRepeatedCallbackInterval(UA_Server *server, UA_UInt64 callbackId,
                                         UA_UInt32 interval);

/* Remove a repeated callback.
 *
 * @param server The server object.
 * @param callbackId The id of the callback that shall be removed.
 * @return Upon success, UA_STATUSCODE_GOOD is returned.
 *         An error code otherwise. */
UA_StatusCode UA_EXPORT
UA_Server_removeRepeatedCallback(UA_Server *server, UA_UInt64 callbackId);

/**
 * Reading and Writing Node Attributes
 * -----------------------------------
 * The functions for reading and writing node attributes call the regular read
 * and write service in the background that are also used over the network.
 *
 * The following attributes cannot be read, since the local "admin" user always
 * has full rights.
 *
 * - UserWriteMask
 * - UserAccessLevel
 * - UserExecutable */
/* Read an attribute of a node. The specialized functions below provide a more
 * concise syntax.
 *
 * @param server The server object.
 * @param item ReadValueIds contain the NodeId of the target node, the id of the
 *             attribute to read and (optionally) an index range to read parts
 *             of an array only. See the section on NumericRange for the format
 *             used for array ranges.
 * @param timestamps Which timestamps to return for the attribute.
 * @return Returns a DataValue that contains either an error code, or a variant
 *         with the attribute value and the timestamps. */
UA_DataValue UA_EXPORT
UA_Server_read(UA_Server *server, const UA_ReadValueId *item,
               UA_TimestampsToReturn timestamps);

/* Don't use this function. There are typed versions for every supported
 * attribute. */
UA_StatusCode UA_EXPORT
__UA_Server_read(UA_Server *server, const UA_NodeId *nodeId,
                 UA_AttributeId attributeId, void *v);

static UA_INLINE UA_StatusCode
UA_Server_readNodeId(UA_Server *server, const UA_NodeId nodeId,
                     UA_NodeId *outNodeId) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_NODEID, outNodeId);
}

static UA_INLINE UA_StatusCode
UA_Server_readNodeClass(UA_Server *server, const UA_NodeId nodeId,
                        UA_NodeClass *outNodeClass) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_NODECLASS,
                            outNodeClass);
}

static UA_INLINE UA_StatusCode
UA_Server_readBrowseName(UA_Server *server, const UA_NodeId nodeId,
                         UA_QualifiedName *outBrowseName) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_BROWSENAME,
                            outBrowseName);
}

static UA_INLINE UA_StatusCode
UA_Server_readDisplayName(UA_Server *server, const UA_NodeId nodeId,
                          UA_LocalizedText *outDisplayName) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_DISPLAYNAME,
                            outDisplayName);
}

static UA_INLINE UA_StatusCode
UA_Server_readDescription(UA_Server *server, const UA_NodeId nodeId,
                          UA_LocalizedText *outDescription) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_DESCRIPTION,
                            outDescription);
}

static UA_INLINE UA_StatusCode
UA_Server_readWriteMask(UA_Server *server, const UA_NodeId nodeId,
                        UA_UInt32 *outWriteMask) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_WRITEMASK,
                            outWriteMask);
}

static UA_INLINE UA_StatusCode
UA_Server_readIsAbstract(UA_Server *server, const UA_NodeId nodeId,
                         UA_Boolean *outIsAbstract) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_ISABSTRACT,
                            outIsAbstract);
}

static UA_INLINE UA_StatusCode
UA_Server_readSymmetric(UA_Server *server, const UA_NodeId nodeId,
                        UA_Boolean *outSymmetric) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_SYMMETRIC,
                            outSymmetric);
}

static UA_INLINE UA_StatusCode
UA_Server_readInverseName(UA_Server *server, const UA_NodeId nodeId,
                          UA_LocalizedText *outInverseName) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_INVERSENAME,
                            outInverseName);
}

static UA_INLINE UA_StatusCode
UA_Server_readContainsNoLoop(UA_Server *server, const UA_NodeId nodeId,
                             UA_Boolean *outContainsNoLoops) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_CONTAINSNOLOOPS,
                            outContainsNoLoops);
}

static UA_INLINE UA_StatusCode
UA_Server_readEventNotifier(UA_Server *server, const UA_NodeId nodeId,
                            UA_Byte *outEventNotifier) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_EVENTNOTIFIER,
                            outEventNotifier);
}

static UA_INLINE UA_StatusCode
UA_Server_readValue(UA_Server *server, const UA_NodeId nodeId,
                    UA_Variant *outValue) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_VALUE, outValue);
}

static UA_INLINE UA_StatusCode
UA_Server_readDataType(UA_Server *server, const UA_NodeId nodeId,
                       UA_NodeId *outDataType) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_DATATYPE,
                            outDataType);
}

static UA_INLINE UA_StatusCode
UA_Server_readValueRank(UA_Server *server, const UA_NodeId nodeId,
                        UA_Int32 *outValueRank) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_VALUERANK,
                            outValueRank);
}

/* Returns a variant with an int32 array */
static UA_INLINE UA_StatusCode
UA_Server_readArrayDimensions(UA_Server *server, const UA_NodeId nodeId,
                              UA_Variant *outArrayDimensions) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_ARRAYDIMENSIONS,
                            outArrayDimensions);
}

static UA_INLINE UA_StatusCode
UA_Server_readAccessLevel(UA_Server *server, const UA_NodeId nodeId,
                          UA_Byte *outAccessLevel) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_ACCESSLEVEL,
                            outAccessLevel);
}

static UA_INLINE UA_StatusCode
UA_Server_readMinimumSamplingInterval(UA_Server *server, const UA_NodeId nodeId,
                                      UA_Double *outMinimumSamplingInterval) {
    return __UA_Server_read(server, &nodeId,
                            UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL,
                            outMinimumSamplingInterval);
}

static UA_INLINE UA_StatusCode
UA_Server_readHistorizing(UA_Server *server, const UA_NodeId nodeId,
                          UA_Boolean *outHistorizing) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_HISTORIZING,
                            outHistorizing);
}

static UA_INLINE UA_StatusCode
UA_Server_readExecutable(UA_Server *server, const UA_NodeId nodeId,
                         UA_Boolean *outExecutable) {
    return __UA_Server_read(server, &nodeId, UA_ATTRIBUTEID_EXECUTABLE,
                            outExecutable);
}

/**
 * The following node attributes cannot be changed once a node has been created:
 *
 * - NodeClass
 * - NodeId
 * - Symmetric
 * - ContainsNoLoop
 *
 * The following attributes cannot be written from the server, as they are
 * specific to the different users and set by the access control callback:
 *
 * - UserWriteMask
 * - UserAccessLevel
 * - UserExecutable
 *
 * Historizing is currently unsupported */

/* Overwrite an attribute of a node. The specialized functions below provide a
 * more concise syntax.
 *
 * @param server The server object.
 * @param value WriteValues contain the NodeId of the target node, the id of the
 *              attribute to overwritten, the actual value and (optionally) an
 *              index range to replace parts of an array only. of an array only.
 *              See the section on NumericRange for the format used for array
 *              ranges.
 * @return Returns a status code. */
UA_StatusCode UA_EXPORT
UA_Server_write(UA_Server *server, const UA_WriteValue *value);

/* Don't use this function. There are typed versions with no additional
 * overhead. */
UA_StatusCode UA_EXPORT
__UA_Server_write(UA_Server *server, const UA_NodeId *nodeId,
                  const UA_AttributeId attributeId,
                  const UA_DataType *attr_type, const void *attr);

static UA_INLINE UA_StatusCode
UA_Server_writeBrowseName(UA_Server *server, const UA_NodeId nodeId,
                          const UA_QualifiedName browseName) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_BROWSENAME,
                             &UA_TYPES[UA_TYPES_QUALIFIEDNAME], &browseName);
}

static UA_INLINE UA_StatusCode
UA_Server_writeDisplayName(UA_Server *server, const UA_NodeId nodeId,
                           const UA_LocalizedText displayName) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_DISPLAYNAME,
                             &UA_TYPES[UA_TYPES_LOCALIZEDTEXT], &displayName);
}

static UA_INLINE UA_StatusCode
UA_Server_writeDescription(UA_Server *server, const UA_NodeId nodeId,
                           const UA_LocalizedText description) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_DESCRIPTION,
                             &UA_TYPES[UA_TYPES_LOCALIZEDTEXT], &description);
}

static UA_INLINE UA_StatusCode
UA_Server_writeWriteMask(UA_Server *server, const UA_NodeId nodeId,
                         const UA_UInt32 writeMask) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_WRITEMASK,
                             &UA_TYPES[UA_TYPES_UINT32], &writeMask);
}

static UA_INLINE UA_StatusCode
UA_Server_writeIsAbstract(UA_Server *server, const UA_NodeId nodeId,
                          const UA_Boolean isAbstract) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_ISABSTRACT,
                             &UA_TYPES[UA_TYPES_BOOLEAN], &isAbstract);
}

static UA_INLINE UA_StatusCode
UA_Server_writeInverseName(UA_Server *server, const UA_NodeId nodeId,
                           const UA_LocalizedText inverseName) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_INVERSENAME,
                             &UA_TYPES[UA_TYPES_LOCALIZEDTEXT], &inverseName);
}

static UA_INLINE UA_StatusCode
UA_Server_writeEventNotifier(UA_Server *server, const UA_NodeId nodeId,
                             const UA_Byte eventNotifier) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_EVENTNOTIFIER,
                             &UA_TYPES[UA_TYPES_BYTE], &eventNotifier);
}

static UA_INLINE UA_StatusCode
UA_Server_writeValue(UA_Server *server, const UA_NodeId nodeId,
                     const UA_Variant value) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_VALUE,
                             &UA_TYPES[UA_TYPES_VARIANT], &value);
}

static UA_INLINE UA_StatusCode
UA_Server_writeDataType(UA_Server *server, const UA_NodeId nodeId,
                        const UA_NodeId dataType) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_DATATYPE,
                             &UA_TYPES[UA_TYPES_NODEID], &dataType);
}

static UA_INLINE UA_StatusCode
UA_Server_writeValueRank(UA_Server *server, const UA_NodeId nodeId,
                         const UA_Int32 valueRank) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_VALUERANK,
                             &UA_TYPES[UA_TYPES_INT32], &valueRank);
}

static UA_INLINE UA_StatusCode
UA_Server_writeArrayDimensions(UA_Server *server, const UA_NodeId nodeId,
                               const UA_Variant arrayDimensions) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_VALUE,
                             &UA_TYPES[UA_TYPES_VARIANT], &arrayDimensions);
}

static UA_INLINE UA_StatusCode
UA_Server_writeAccessLevel(UA_Server *server, const UA_NodeId nodeId,
                           const UA_Byte accessLevel) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_ACCESSLEVEL,
                             &UA_TYPES[UA_TYPES_BYTE], &accessLevel);
}

static UA_INLINE UA_StatusCode
UA_Server_writeMinimumSamplingInterval(UA_Server *server, const UA_NodeId nodeId,
                                       const UA_Double miniumSamplingInterval) {
    return __UA_Server_write(server, &nodeId,
                             UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL,
                             &UA_TYPES[UA_TYPES_DOUBLE],
                             &miniumSamplingInterval);
}

static UA_INLINE UA_StatusCode
UA_Server_writeExecutable(UA_Server *server, const UA_NodeId nodeId,
                          const UA_Boolean executable) {
    return __UA_Server_write(server, &nodeId, UA_ATTRIBUTEID_EXECUTABLE,
                             &UA_TYPES[UA_TYPES_BOOLEAN], &executable); }

/**
 * Browsing
 * -------- */
UA_BrowseResult UA_EXPORT
UA_Server_browse(UA_Server *server, UA_UInt32 maxrefs,
                 const UA_BrowseDescription *descr);

UA_BrowseResult UA_EXPORT
UA_Server_browseNext(UA_Server *server, UA_Boolean releaseContinuationPoint,
                     const UA_ByteString *continuationPoint);

UA_BrowsePathResult UA_EXPORT
UA_Server_translateBrowsePathToNodeIds(UA_Server *server,
                                       const UA_BrowsePath *browsePath);

#ifndef HAVE_NODEITER_CALLBACK
#define HAVE_NODEITER_CALLBACK
/* Iterate over all nodes referenced by parentNodeId by calling the callback
 * function for each child node (in ifdef because GCC/CLANG handle include order
 * differently) */
typedef UA_StatusCode
(*UA_NodeIteratorCallback)(UA_NodeId childId, UA_Boolean isInverse,
                           UA_NodeId referenceTypeId, void *handle);
#endif

UA_StatusCode UA_EXPORT
UA_Server_forEachChildNodeCall(UA_Server *server, UA_NodeId parentNodeId,
                               UA_NodeIteratorCallback callback, void *handle);

#ifdef UA_ENABLE_DISCOVERY

/**
 * Discovery
 * --------- */
/* Register the given server instance at the discovery server.
 * This should be called periodically.
 * The semaphoreFilePath is optional. If the given file is deleted,
 * the server will automatically be unregistered. This could be
 * for example a pid file which is deleted if the server crashes.
 *
 * When the server shuts down you need to call unregister.
 *
 * @param server
 * @param discoveryServerUrl if set to NULL, the default value
 *        'opc.tcp://localhost:4840' will be used
 * @param semaphoreFilePath optional parameter pointing to semaphore file. */
UA_StatusCode UA_EXPORT
UA_Server_register_discovery(UA_Server *server, const char* discoveryServerUrl,
                             const char* semaphoreFilePath);

/* Unregister the given server instance from the discovery server.
 * This should only be called when the server is shutting down.
 * @param server
 * @param discoveryServerUrl if set to NULL, the default value
 *        'opc.tcp://localhost:4840' will be used */
UA_StatusCode UA_EXPORT
UA_Server_unregister_discovery(UA_Server *server, const char* discoveryServerUrl);

 /* Adds a periodic callback to register the server with the LDS (local discovery server)
  * periodically. The interval between each register call is given as second parameter.
  * It should be 10 minutes by default (= 10*60*1000).
  *
  * The delayFirstRegisterMs parameter indicates the delay for the first register call.
  * If it is 0, the first register call will be after intervalMs milliseconds,
  * otherwise the server's first register will be after delayFirstRegisterMs.
  *
  * When you manually unregister the server, you also need to cancel the
  * periodic callback, otherwise it will be automatically be registered again.
  *
  * If you call this method multiple times for the same discoveryServerUrl, the older
  * periodic callback will be removed.
  *
  * @param server
  * @param discoveryServerUrl if set to NULL, the default value
  *        'opc.tcp://localhost:4840' will be used
  * @param intervalMs
  * @param delayFirstRegisterMs
  * @param periodicCallbackId */
UA_StatusCode UA_EXPORT
UA_Server_addPeriodicServerRegisterCallback(UA_Server *server, const char* discoveryServerUrl,
                                            UA_UInt32 intervalMs,
                                            UA_UInt32 delayFirstRegisterMs,
                                            UA_UInt64 *periodicCallbackId);

/* Callback for RegisterServer. Data is passed from the register call */
typedef void (*UA_Server_registerServerCallback)(const UA_RegisteredServer *registeredServer,
                                                 void* data);

/* Set the callback which is called if another server registeres or unregisters
 * with this instance. If called multiple times, previous data will be
 * overwritten.
 *
 * @param server
 * @param cb the callback
 * @param data data passed to the callback
 * @return UA_STATUSCODE_SUCCESS on success */
void UA_EXPORT
UA_Server_setRegisterServerCallback(UA_Server *server, UA_Server_registerServerCallback cb,
                                    void* data);

#ifdef UA_ENABLE_DISCOVERY_MULTICAST

/* Callback for server detected through mDNS. Data is passed from the register
 * call
 *
 * @param isServerAnnounce indicates if the server has just been detected. If
 *        set to false, this means the server is shutting down.
 * @param isTxtReceived indicates if we already received the corresponding TXT
 *        record with the path and caps data */
typedef void (*UA_Server_serverOnNetworkCallback)(const UA_ServerOnNetwork *serverOnNetwork,
                                                  UA_Boolean isServerAnnounce,
                                                  UA_Boolean isTxtReceived, void* data);

/* Set the callback which is called if another server is found through mDNS or
 * deleted. It will be called for any mDNS message from the remote server, thus
 * it may be called multiple times for the same instance. Also the SRV and TXT
 * records may arrive later, therefore for the first call the server
 * capabilities may not be set yet. If called multiple times, previous data will
 * be overwritten.
 *
 * @param server
 * @param cb the callback
 * @param data data passed to the callback
 * @return UA_STATUSCODE_SUCCESS on success */
void UA_EXPORT
UA_Server_setServerOnNetworkCallback(UA_Server *server,
                                     UA_Server_serverOnNetworkCallback cb,
                                     void* data);

#endif /* UA_ENABLE_DISCOVERY_MULTICAST */

#endif /* UA_ENABLE_DISCOVERY */

/**
 * Information Model Callbacks
 * ---------------------------
 *
 * There are three places where a callback from an information model to
 * user-defined code can happen.
 *
 * - Custom node constructors and destructors
 * - Linking VariableNodes with an external data source
 * - MethodNode callbacks
 *
 * .. _node-lifecycle:
 *
 * Node Lifecycle: Constructors, Destructors and Node Contexts
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *
 * To finalize the instantiation of a node, a (user-defined) constructor
 * callback is executed. There can be both a global constructor for all nodes
 * and node-type constructor specific to the TypeDefinition of the new node
 * (attached to an ObjectTypeNode or VariableTypeNode).
 *
 * In the hierarchy of ObjectTypes and VariableTypes, only the constructor of
 * the (lowest) type defined for the new node is executed. Note that every
 * Object and Variable can have only one ``isTypeOf`` reference. But type-nodes
 * can technically have several ``hasSubType`` references to implement multiple
 * inheritance. Issues of (multiple) inheritance in the constructor need to be
 * solved by the user.
 *
 * When a node is destroyed, the node-type destructor is called before the
 * global destructor. So the overall node lifecycle is as follows:
 *
 * 1. Global Constructor (set in the server config)
 * 2. Node-Type Constructor (for VariableType or ObjectTypes)
 * 3. (Usage-period of the Node)
 * 4. Node-Type Destructor
 * 5. Global Destructor
 *
 * The constructor and destructor callbacks can be set to ``NULL`` and are not
 * used in that case. If the node-type constructor fails, the global destructor
 * will be called before removing the node. The destructors are assumed to never
 * fail.
 *
 * Every node carries a user-context and a constructor-context pointer. The
 * user-context is used to attach custom data to a node. But the (user-defined)
 * constructors and destructors may replace the user-context pointer if they
 * wish to do so. The initial value for the constructor-context is ``NULL``.
 * When the ``AddNodes`` service is used over the network, the user-context
 * pointer of the new node is also initially set to ``NULL``. */

/* To be set in the server config. */
typedef struct {
    /* Can be NULL. May replace the nodeContext */
    UA_StatusCode (*constructor)(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *nodeId, void **nodeContext);

    /* Can be NULL. The context cannot be replaced since the node is destroyed
     * immediately afterwards anyway. */
    void (*destructor)(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionContext,
                       const UA_NodeId *nodeId, void *nodeContext);
} UA_GlobalNodeLifecycle;

typedef struct {
    /* Can be NULL. May replace the nodeContext */
    UA_StatusCode (*constructor)(UA_Server *server,
                                 const UA_NodeId *sessionId, void *sessionContext,
                                 const UA_NodeId *typeNodeId, void *typeNodeContext,
                                 const UA_NodeId *nodeId, void **nodeContext);

    /* Can be NULL. May replace the nodeContext. */
    void (*destructor)(UA_Server *server,
                       const UA_NodeId *sessionId, void *sessionContext,
                       const UA_NodeId *typeNodeId, void *typeNodeContext,
                       const UA_NodeId *nodeId, void **nodeContext);
} UA_NodeTypeLifecycle;

UA_StatusCode UA_EXPORT
UA_Server_setNodeTypeLifecycle(UA_Server *server, UA_NodeId nodeId,
                               UA_NodeTypeLifecycle lifecycle);

UA_StatusCode UA_EXPORT
UA_Server_getNodeContext(UA_Server *server, UA_NodeId nodeId,
                         void **nodeContext);

/* Careful! The user has to ensure that the destructor callbacks still work. */
UA_StatusCode UA_EXPORT
UA_Server_setNodeContext(UA_Server *server, UA_NodeId nodeId,
                         void *nodeContext);

/**
 * .. _datasource:
 *
 * Data Source Callback
 * ^^^^^^^^^^^^^^^^^^^^
 *
 * The server has a unique way of dealing with the content of variables. Instead
 * of storing a variant attached to the variable node, the node can point to a
 * function with a local data provider. Whenever the value attribute is read,
 * the function will be called and asked to provide a UA_DataValue return value
 * that contains the value content and additional timestamps.
 *
 * It is expected that the read callback is implemented. The write callback can
 * be set to a null-pointer. */
typedef struct {
    /* Copies the data from the source into the provided value.
     *
     * !! ZERO-COPY OPERATIONS POSSIBLE !!
     * It is not required to return a copy of the actual content data. You can
     * return a pointer to memory owned by the user. Memory can be reused
     * between read callbacks of a DataSource, as the result is already encoded
     * on the network buffer between each read operation.
     *
     * To use zero-copy reads, set the value of the `value->value` Variant
     * without copying, e.g. with `UA_Variant_setScalar`. Then, also set
     * `value->value.storageType` to `UA_VARIANT_DATA_NODELETE` to prevent the
     * memory being cleaned up. Don't forget to also set `value->hasValue` to
     * true to indicate the presence of a value.
     *
     * @param handle An optional pointer to user-defined data for the
     *        specific data source
     * @param nodeid Id of the read node
     * @param includeSourceTimeStamp If true, then the datasource is expected to
     *        set the source timestamp in the returned value
     * @param range If not null, then the datasource shall return only a
     *        selection of the (nonscalar) data. Set
     *        UA_STATUSCODE_BADINDEXRANGEINVALID in the value if this does not
     *        apply.
     * @param value The (non-null) DataValue that is returned to the client. The
     *        data source sets the read data, the result status and optionally a
     *        sourcetimestamp.
     * @return Returns a status code for logging. Error codes intended for the
     *         original caller are set in the value. If an error is returned,
     *         then no releasing of the value is done. */
    UA_StatusCode (*read)(UA_Server *server, const UA_NodeId *sessionId,
                          void *sessionContext, const UA_NodeId *nodeId,
                          void *nodeContext, UA_Boolean includeSourceTimeStamp,
                          const UA_NumericRange *range, UA_DataValue *value);

    /* Write into a data source. This method pointer can be NULL if the
     * operation is unsupported.
     *
     * @param handle An optional pointer to user-defined data for the
     *        specific data source
     * @param nodeid Id of the node being written to
     * @param data The data to be written into the data source
     * @param range An optional data range. If the data source is scalar or does
     *        not support writing of ranges, then an error code is returned.
     * @return Returns a status code that is returned to the user */
    UA_StatusCode (*write)(UA_Server *server, const UA_NodeId *sessionId,
                           void *sessionContext, const UA_NodeId *nodeId,
                           void *nodeContext, const UA_NumericRange *range,
                           const UA_DataValue *value);
} UA_DataSource;

UA_StatusCode UA_EXPORT
UA_Server_setVariableNode_dataSource(UA_Server *server, const UA_NodeId nodeId,
                                     const UA_DataSource dataSource);

/**
 * .. _value-callback:
 *
 * Value Callback
 * ^^^^^^^^^^^^^^
 * Value Callbacks can be attached to variable and variable type nodes. If
 * not ``NULL``, they are called before reading and after writing respectively. */
typedef struct {
    /* Called before the value attribute is read. It is possible to write into the
     * value attribute during onRead (using the write service). The node is
     * re-opened afterwards so that changes are considered in the following read
     * operation.
     *
     * @param handle Points to user-provided data for the callback.
     * @param nodeid The identifier of the node.
     * @param data Points to the current node value.
     * @param range Points to the numeric range the client wants to read from
     *        (or NULL). */
    void (*onRead)(UA_Server *server, const UA_NodeId *sessionId,
                   void *sessionContext, const UA_NodeId *nodeid,
                   void *nodeContext, const UA_NumericRange *range,
                   const UA_DataValue *value);

    /* Called after writing the value attribute. The node is re-opened after
     * writing so that the new value is visible in the callback.
     *
     * @param server The server executing the callback
     * @sessionId The identifier of the session
     * @sessionContext Additional data attached to the session
     *                 in the access control layer
     * @param nodeid The identifier of the node.
     * @param nodeUserContext Additional data attached to the node by
     *        the user.
     * @param nodeConstructorContext Additional data attached to the node
     *        by the type constructor(s).
     * @param range Points to the numeric range the client wants to write to (or
     *        NULL). */
    void (*onWrite)(UA_Server *server, const UA_NodeId *sessionId,
                    void *sessionContext, const UA_NodeId *nodeId,
                    void *nodeContext, const UA_NumericRange *range,
                    const UA_DataValue *data);
} UA_ValueCallback;

UA_StatusCode UA_EXPORT
UA_Server_setVariableNode_valueCallback(UA_Server *server,
                                        const UA_NodeId nodeId,
                                        const UA_ValueCallback callback);

/**
 * Method Callbacks
 * ^^^^^^^^^^^^^^^^
 * Method callbacks are set to `NULL` (not executable) when a method node is added
 * over the network. In theory, it is possible to add a callback via
 * ``UA_Server_setMethodNode_callback`` within the global constructor when adding
 * methods over the network is really wanted. */

typedef UA_StatusCode
(*UA_MethodCallback)(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_NodeId *methodId,
                     void *methodContext, const UA_NodeId *objectId,
                     void *objectContext, size_t inputSize,
                     const UA_Variant *input, size_t outputSize,
                     UA_Variant *output);

#ifdef UA_ENABLE_METHODCALLS

UA_StatusCode UA_EXPORT
UA_Server_setMethodNode_callback(UA_Server *server,
                                 const UA_NodeId methodNodeId,
                                 UA_MethodCallback methodCallback);
UA_CallMethodResult UA_EXPORT
UA_Server_call(UA_Server *server, const UA_CallMethodRequest *request);

#endif

/**
 * .. _addnodes:
 *
 * Node Addition and Deletion
 * --------------------------
 * When creating dynamic node instances at runtime, chances are that you will
 * not care about the specific NodeId of the new node, as long as you can
 * reference it later. When passing numeric NodeIds with a numeric identifier 0,
 * the stack evaluates this as "select a random unassigned numeric NodeId in
 * that namespace". To find out which NodeId was actually assigned to the new
 * node, you may pass a pointer `outNewNodeId`, which will (after a successful
 * node insertion) contain the nodeId of the new node. You may also pass a
 * ``NULL`` pointer if this result is not needed.
 *
 * See the Section :ref:`node-lifecycle` on constructors and on attaching
 * user-defined data to nodes.
 *
 * The methods for node addition and deletion take mostly const arguments that
 * are not modified. When creating a node, a deep copy of the node identifier,
 * node attributes, etc. is created. Therefore, it is possible to call for
 * example ``UA_Server_addVariablenode`` with a value attribute (a
 * :ref:`variant`) pointing to a memory location on the stack. If you need
 * changes to a variable value to manifest at a specific memory location, please
 * use a :ref:`datasource` or a :ref:`value-callback`. */

/* Protect against redundant definitions for server/client */
#ifndef UA_DEFAULT_ATTRIBUTES_DEFINED
#define UA_DEFAULT_ATTRIBUTES_DEFINED
/* The default for variables is "BaseDataType" for the datatype, -2 for the
 * valuerank and a read-accesslevel. */
UA_EXPORT extern const UA_VariableAttributes UA_VariableAttributes_default;
UA_EXPORT extern const UA_VariableTypeAttributes UA_VariableTypeAttributes_default;
/* Methods are executable by default */
UA_EXPORT extern const UA_MethodAttributes UA_MethodAttributes_default;
/* The remaining attribute definitions are currently all zeroed out */
UA_EXPORT extern const UA_ObjectAttributes UA_ObjectAttributes_default;
UA_EXPORT extern const UA_ObjectTypeAttributes UA_ObjectTypeAttributes_default;
UA_EXPORT extern const UA_ReferenceTypeAttributes UA_ReferenceTypeAttributes_default;
UA_EXPORT extern const UA_DataTypeAttributes UA_DataTypeAttributes_default;
UA_EXPORT extern const UA_ViewAttributes UA_ViewAttributes_default;
#endif

/* Don't use this function. There are typed versions as inline functions. */
UA_StatusCode UA_EXPORT
__UA_Server_addNode(UA_Server *server, const UA_NodeClass nodeClass,
                    const UA_NodeId *requestedNewNodeId,
                    const UA_NodeId *parentNodeId,
                    const UA_NodeId *referenceTypeId,
                    const UA_QualifiedName browseName,
                    const UA_NodeId *typeDefinition,
                    const UA_NodeAttributes *attr,
                    const UA_DataType *attributeType,
                    void *nodeContext, UA_NodeId *outNewNodeId);

static UA_INLINE UA_StatusCode
UA_Server_addVariableNode(UA_Server *server, const UA_NodeId requestedNewNodeId,
                          const UA_NodeId parentNodeId,
                          const UA_NodeId referenceTypeId,
                          const UA_QualifiedName browseName,
                          const UA_NodeId typeDefinition,
                          const UA_VariableAttributes attr,
                          void *nodeContext, UA_NodeId *outNewNodeId) {
    return __UA_Server_addNode(server, UA_NODECLASS_VARIABLE, &requestedNewNodeId,
                               &parentNodeId, &referenceTypeId, browseName,
                               &typeDefinition, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES],
                               nodeContext, outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Server_addVariableTypeNode(UA_Server *server,
                              const UA_NodeId requestedNewNodeId,
                              const UA_NodeId parentNodeId,
                              const UA_NodeId referenceTypeId,
                              const UA_QualifiedName browseName,
                              const UA_NodeId typeDefinition,
                              const UA_VariableTypeAttributes attr,
                              void *nodeContext, UA_NodeId *outNewNodeId) {
    return __UA_Server_addNode(server, UA_NODECLASS_VARIABLETYPE,
                               &requestedNewNodeId, &parentNodeId, &referenceTypeId,
                               browseName, &typeDefinition,
                               (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_VARIABLETYPEATTRIBUTES],
                               nodeContext, outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Server_addObjectNode(UA_Server *server, const UA_NodeId requestedNewNodeId,
                        const UA_NodeId parentNodeId,
                        const UA_NodeId referenceTypeId,
                        const UA_QualifiedName browseName,
                        const UA_NodeId typeDefinition,
                        const UA_ObjectAttributes attr,
                        void *nodeContext, UA_NodeId *outNewNodeId) {
    return __UA_Server_addNode(server, UA_NODECLASS_OBJECT, &requestedNewNodeId,
                               &parentNodeId, &referenceTypeId, browseName,
                               &typeDefinition, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES],
                               nodeContext, outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Server_addObjectTypeNode(UA_Server *server, const UA_NodeId requestedNewNodeId,
                            const UA_NodeId parentNodeId,
                            const UA_NodeId referenceTypeId,
                            const UA_QualifiedName browseName,
                            const UA_ObjectTypeAttributes attr,
                            void *nodeContext, UA_NodeId *outNewNodeId) {
    return __UA_Server_addNode(server, UA_NODECLASS_OBJECTTYPE, &requestedNewNodeId,
                               &parentNodeId, &referenceTypeId, browseName,
                               &UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_OBJECTTYPEATTRIBUTES],
                               nodeContext, outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Server_addViewNode(UA_Server *server, const UA_NodeId requestedNewNodeId,
                      const UA_NodeId parentNodeId,
                      const UA_NodeId referenceTypeId,
                      const UA_QualifiedName browseName,
                      const UA_ViewAttributes attr,
                      void *nodeContext, UA_NodeId *outNewNodeId) {
    return __UA_Server_addNode(server, UA_NODECLASS_VIEW, &requestedNewNodeId,
                               &parentNodeId, &referenceTypeId, browseName,
                               &UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_VIEWATTRIBUTES],
                               nodeContext, outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Server_addReferenceTypeNode(UA_Server *server,
                               const UA_NodeId requestedNewNodeId,
                               const UA_NodeId parentNodeId,
                               const UA_NodeId referenceTypeId,
                               const UA_QualifiedName browseName,
                               const UA_ReferenceTypeAttributes attr,
                               void *nodeContext, UA_NodeId *outNewNodeId) {
    return __UA_Server_addNode(server, UA_NODECLASS_REFERENCETYPE,
                               &requestedNewNodeId, &parentNodeId, &referenceTypeId,
                               browseName, &UA_NODEID_NULL,
                               (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_REFERENCETYPEATTRIBUTES],
                               nodeContext, outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Server_addDataTypeNode(UA_Server *server,
                          const UA_NodeId requestedNewNodeId,
                          const UA_NodeId parentNodeId,
                          const UA_NodeId referenceTypeId,
                          const UA_QualifiedName browseName,
                          const UA_DataTypeAttributes attr,
                          void *nodeContext, UA_NodeId *outNewNodeId) {
    return __UA_Server_addNode(server, UA_NODECLASS_DATATYPE, &requestedNewNodeId,
                               &parentNodeId, &referenceTypeId, browseName,
                               &UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_DATATYPEATTRIBUTES],
                               nodeContext, outNewNodeId);
}

UA_StatusCode UA_EXPORT
UA_Server_addDataSourceVariableNode(UA_Server *server,
                                    const UA_NodeId requestedNewNodeId,
                                    const UA_NodeId parentNodeId,
                                    const UA_NodeId referenceTypeId,
                                    const UA_QualifiedName browseName,
                                    const UA_NodeId typeDefinition,
                                    const UA_VariableAttributes attr,
                                    const UA_DataSource dataSource,
                                    void *nodeContext, UA_NodeId *outNewNodeId);

UA_StatusCode UA_EXPORT
UA_Server_addMethodNodeEx(UA_Server *server, const UA_NodeId requestedNewNodeId,
                          const UA_NodeId parentNodeId,
                          const UA_NodeId referenceTypeId,
                          const UA_QualifiedName browseName,
                          const UA_MethodAttributes attr, UA_MethodCallback method,
                          size_t inputArgumentsSize, const UA_Argument *inputArguments,
                          const UA_NodeId inputArgumentsRequestedNewNodeId,
                          UA_NodeId *inputArgumentsOutNewNodeId,
                          size_t outputArgumentsSize, const UA_Argument *outputArguments,
                          const UA_NodeId outputArgumentsRequestedNewNodeId,
                          UA_NodeId *outputArgumentsOutNewNodeId,
                          void *nodeContext, UA_NodeId *outNewNodeId);

static UA_INLINE UA_StatusCode
UA_Server_addMethodNode(UA_Server *server, const UA_NodeId requestedNewNodeId,
                        const UA_NodeId parentNodeId, const UA_NodeId referenceTypeId,
                        const UA_QualifiedName browseName, const UA_MethodAttributes attr,
                        UA_MethodCallback method,
                        size_t inputArgumentsSize, const UA_Argument *inputArguments,
                        size_t outputArgumentsSize, const UA_Argument *outputArguments,
                        void *nodeContext, UA_NodeId *outNewNodeId) {
    return UA_Server_addMethodNodeEx(server, requestedNewNodeId,  parentNodeId,
                                     referenceTypeId, browseName, attr, method,
                                     inputArgumentsSize, inputArguments, UA_NODEID_NULL, NULL,
                                     outputArgumentsSize, outputArguments, UA_NODEID_NULL, NULL,
                                     nodeContext, outNewNodeId);
}


/**
 * The method pair UA_Server_addNode_begin and _finish splits the AddNodes
 * service in two parts. This is useful if the node shall be modified before
 * finish the instantiation. For example to add children with specific NodeIds.
 * Otherwise, mandatory children (e.g. of an ObjectType) are added with
 * pseudo-random unique NodeIds. Existing children are detected during the
 * _finish part via their matching BrowseName.
 *
 * The _begin method:
 *  - prepares the node and adds it to the nodestore
 *  - copies some unassigned attributes from the TypeDefinition node internally
 *  - adds the references to the parent (and the TypeDefinition if applicable)
 *  - performs type-checking of variables.
 *
 * You can add an object node without a parent if you set the parentNodeId and
 * referenceTypeId to UA_NODE_ID_NULL. Then you need to add the parent reference
 * and hasTypeDef reference yourself before calling the _finish method.
 * Not that this is only allowed for object nodes.
 *
 * The _finish method:
 *  - copies mandatory children
 *  - calls the node constructor(s) at the end
 *  - may remove the node if it encounters an error.
 *
 * The special UA_Server_addMethodNode_finish method needs to be used for
 * method nodes, since there you need to explicitly specifiy the input
 * and output arguments which are added in the finish step (if not yet already there)
 **/

/* The ``attr`` argument must have a type according to the NodeClass.
 * ``VariableAttributes`` for variables, ``ObjectAttributes`` for objects, and
 * so on. Missing attributes are taken from the TypeDefinition node if
 * applicable. */
UA_StatusCode UA_EXPORT
UA_Server_addNode_begin(UA_Server *server, const UA_NodeClass nodeClass,
                        const UA_NodeId requestedNewNodeId,
                        const UA_NodeId parentNodeId,
                        const UA_NodeId referenceTypeId,
                        const UA_QualifiedName browseName,
                        const UA_NodeId typeDefinition,
                        const void *attr, const UA_DataType *attributeType,
                        void *nodeContext, UA_NodeId *outNewNodeId);

UA_StatusCode UA_EXPORT
UA_Server_addNode_finish(UA_Server *server, const UA_NodeId nodeId);

UA_StatusCode UA_EXPORT
UA_Server_addMethodNode_finish(UA_Server *server, const UA_NodeId nodeId,
                         UA_MethodCallback method,
                         size_t inputArgumentsSize, const UA_Argument* inputArguments,
                         size_t outputArgumentsSize, const UA_Argument* outputArguments);

/* Deletes a node and optionally all references leading to the node. */
UA_StatusCode UA_EXPORT
UA_Server_deleteNode(UA_Server *server, const UA_NodeId nodeId,
                     UA_Boolean deleteReferences);

/**
 * Reference Management
 * -------------------- */
UA_StatusCode UA_EXPORT
UA_Server_addReference(UA_Server *server, const UA_NodeId sourceId,
                       const UA_NodeId refTypeId,
                       const UA_ExpandedNodeId targetId, UA_Boolean isForward);

UA_StatusCode UA_EXPORT
UA_Server_deleteReference(UA_Server *server, const UA_NodeId sourceNodeId,
                          const UA_NodeId referenceTypeId, UA_Boolean isForward,
                          const UA_ExpandedNodeId targetNodeId,
                          UA_Boolean deleteBidirectional);

/**
 * Utility Functions
 * ----------------- */
/* Add a new namespace to the server. Returns the index of the new namespace */
UA_UInt16 UA_EXPORT UA_Server_addNamespace(UA_Server *server, const char* name);

/**
 * Deprecated Server API
 * ---------------------
 * This file contains outdated API definitions that are kept for backwards
 * compatibility. Please switch to the new API, as the following definitions
 * will be removed eventually.
 *
 * UA_Job API
 * ^^^^^^^^^^
 * UA_Job was replaced since it unnecessarily exposed server internals to the
 * end-user. Please use plain UA_ServerCallbacks instead. The following UA_Job
 * definition contains just the fraction of the original struct that was useful
 * to end-users. */

typedef enum {
    UA_JOBTYPE_METHODCALL
} UA_JobType;

typedef struct {
    UA_JobType type;
    union {
        struct {
            void *data;
            UA_ServerCallback method;
        } methodCall;
    } job;
} UA_Job;

UA_DEPRECATED static UA_INLINE UA_StatusCode
UA_Server_addRepeatedJob(UA_Server *server, UA_Job job,
                         UA_UInt32 interval, UA_Guid *jobId) {
    return UA_Server_addRepeatedCallback(server, job.job.methodCall.method,
                                         job.job.methodCall.data, interval,
                                         (UA_UInt64*)(uintptr_t)jobId);
}

UA_DEPRECATED static UA_INLINE UA_StatusCode
UA_Server_removeRepeatedJob(UA_Server *server, UA_Guid jobId) {
    return UA_Server_removeRepeatedCallback(server,
                                            *(UA_UInt64*)(uintptr_t)&jobId);
}

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_plugin_log.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this 
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */


#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>

/**
 * Logging Plugin API
 * ==================
 *
 * Servers and clients must define a logger in their configuration. The logger
 * is just a function pointer. Every log-message consists of a log-level, a
 * log-category and a string message content. The timestamp of the log-message
 * is created within the logger. */

typedef enum {
    UA_LOGLEVEL_TRACE,
    UA_LOGLEVEL_DEBUG,
    UA_LOGLEVEL_INFO,
    UA_LOGLEVEL_WARNING,
    UA_LOGLEVEL_ERROR,
    UA_LOGLEVEL_FATAL
} UA_LogLevel;

typedef enum {
    UA_LOGCATEGORY_NETWORK,
    UA_LOGCATEGORY_SECURECHANNEL,
    UA_LOGCATEGORY_SESSION,
    UA_LOGCATEGORY_SERVER,
    UA_LOGCATEGORY_CLIENT,
    UA_LOGCATEGORY_USERLAND,
    UA_LOGCATEGORY_SECURITYPOLICY
} UA_LogCategory;

/**
 * The message string and following varargs are formatted according to the rules
 * of the printf command. Do not call the logger directly. Instead, make use of
 * the convenience macros that take the minimum log-level defined in ua_config.h
 * into account. */

typedef void (*UA_Logger)(UA_LogLevel level, UA_LogCategory category,
                          const char *msg, va_list args);

static UA_INLINE UA_FORMAT(3,4) void
UA_LOG_TRACE(UA_Logger logger, UA_LogCategory category, const char *msg, ...) {
#if UA_LOGLEVEL <= 100
    va_list args; va_start(args, msg);
    logger(UA_LOGLEVEL_TRACE, category, msg, args);
    va_end(args);
#endif
}

static UA_INLINE UA_FORMAT(3,4) void
UA_LOG_DEBUG(UA_Logger logger, UA_LogCategory category, const char *msg, ...) {
#if UA_LOGLEVEL <= 200
    va_list args; va_start(args, msg);
    logger(UA_LOGLEVEL_DEBUG, category, msg, args);
    va_end(args);
#endif
}

static UA_INLINE UA_FORMAT(3,4) void
UA_LOG_INFO(UA_Logger logger, UA_LogCategory category, const char *msg, ...) {
#if UA_LOGLEVEL <= 300
    va_list args; va_start(args, msg);
    logger(UA_LOGLEVEL_INFO, category, msg, args);
    va_end(args);
#endif
}

static UA_INLINE UA_FORMAT(3,4) void
UA_LOG_WARNING(UA_Logger logger, UA_LogCategory category, const char *msg, ...) {
#if UA_LOGLEVEL <= 400
    va_list args; va_start(args, msg);
    logger(UA_LOGLEVEL_WARNING, category, msg, args);
    va_end(args);
#endif
}

static UA_INLINE UA_FORMAT(3,4) void
UA_LOG_ERROR(UA_Logger logger, UA_LogCategory category, const char *msg, ...) {
#if UA_LOGLEVEL <= 500
    va_list args; va_start(args, msg);
    logger(UA_LOGLEVEL_ERROR, category, msg, args);
    va_end(args);
#endif
}

static UA_INLINE UA_FORMAT(3,4) void
UA_LOG_FATAL(UA_Logger logger, UA_LogCategory category, const char *msg, ...) {
#if UA_LOGLEVEL <= 600
    va_list args; va_start(args, msg);
    logger(UA_LOGLEVEL_FATAL, category, msg, args);
    va_end(args);
#endif
}

/**
 * Convenience macros for complex types
 * ------------------------------------ */
#define UA_PRINTF_GUID_FORMAT "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define UA_PRINTF_GUID_DATA(GUID) (GUID).data1, (GUID).data2, (GUID).data3, \
        (GUID).data4[0], (GUID).data4[1], (GUID).data4[2], (GUID).data4[3], \
        (GUID).data4[4], (GUID).data4[5], (GUID).data4[6], (GUID).data4[7]

#define UA_PRINTF_STRING_FORMAT "\"%.*s\""
#define UA_PRINTF_STRING_DATA(STRING) (int)(STRING).length, (STRING).data


#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_plugin_network.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */


#ifdef __cplusplus
extern "C" {
#endif


/* Forward declarations */
struct UA_Connection;
typedef struct UA_Connection UA_Connection;

struct UA_SecureChannel;
typedef struct UA_SecureChannel UA_SecureChannel;

struct UA_ServerNetworkLayer;
typedef struct UA_ServerNetworkLayer UA_ServerNetworkLayer;

/**
 * .. _networking:
 * 
 * Networking Plugin API
 * =====================
 *
 * Connection
 * ----------
 * Client-server connections are represented by a `UA_Connection`. The
 * connection is stateful and stores partially received messages, and so on. In
 * addition, the connection contains function pointers to the underlying
 * networking implementation. An example for this is the `send` function. So the
 * connection encapsulates all the required networking functionality. This lets
 * users on embedded (or otherwise exotic) systems implement their own
 * networking plugins with a clear interface to the main open62541 library. */

typedef struct {
    UA_UInt32 protocolVersion;
    UA_UInt32 sendBufferSize;
    UA_UInt32 recvBufferSize;
    UA_UInt32 maxMessageSize;
    UA_UInt32 maxChunkCount;
} UA_ConnectionConfig;

typedef enum {
    UA_CONNECTION_CLOSED,      /* The socket has been closed and the connection
                                * will be deleted */
    UA_CONNECTION_OPENING,     /* The socket is open, but the HEL/ACK handshake
                                * is not done */
    UA_CONNECTION_ESTABLISHED  /* The socket is open and the connection
                                * configured */
} UA_ConnectionState;

struct UA_Connection {
    UA_ConnectionState state;
    UA_ConnectionConfig localConf;
    UA_ConnectionConfig remoteConf;
    UA_SecureChannel *channel;       /* The securechannel that is attached to
                                      * this connection */
    UA_Int32 sockfd;                 /* Most connectivity solutions run on
                                      * sockets. Having the socket id here
                                      * simplifies the design. */
    UA_DateTime openingDate;         /* The date the connection was created */
    void *handle;                    /* A pointer to internal data */
    UA_ByteString incompleteMessage; /* A half-received chunk (TCP is a
                                      * streaming protocol) is stored here */

    /* Get a buffer for sending */
    UA_StatusCode (*getSendBuffer)(UA_Connection *connection, size_t length,
                                   UA_ByteString *buf);

    /* Release the send buffer manually */
    void (*releaseSendBuffer)(UA_Connection *connection, UA_ByteString *buf);

    /* Sends a message over the connection. The message buffer is always freed,
     * even if sending fails.
     *
     * @param connection The connection
     * @param buf The message buffer
     * @return Returns an error code or UA_STATUSCODE_GOOD. */
    UA_StatusCode (*send)(UA_Connection *connection, UA_ByteString *buf);

    /* Receive a message from the remote connection
     *
     * @param connection The connection
     * @param response The response string. It is allocated by the connection
     *        and needs to be freed with connection->releaseBuffer
     * @param timeout Timeout of the recv operation in milliseconds
     * @return Returns UA_STATUSCODE_BADCOMMUNICATIONERROR if the recv operation
     *         can be repeated, UA_STATUSCODE_GOOD if it succeeded and
     *         UA_STATUSCODE_BADCONNECTIONCLOSED if the connection was
     *         closed. */
    UA_StatusCode (*recv)(UA_Connection *connection, UA_ByteString *response,
                          UA_UInt32 timeout);

    /* Release the buffer of a received message */
    void (*releaseRecvBuffer)(UA_Connection *connection, UA_ByteString *buf);

    /* Close the connection. The network layer closes the socket. This is picked
     * up during the next 'listen' and the connection is freed in the network
     * layer. */
    void (*close)(UA_Connection *connection);

    /* To be called only from within the server (and not the network layer).
     * Frees up the connection's memory. */
    void (*free)(UA_Connection *connection);

    /* A message has not been processed yet */
    UA_Boolean pendingMessage;
};

/* Cleans up half-received messages, and so on. Called from connection->free. */
void UA_EXPORT
UA_Connection_deleteMembers(UA_Connection *connection);

/**
 * Server Network Layer
 * --------------------
 * The server exposes two functions to interact with remote clients:
 * `processBinaryMessage` and `removeConnection`. These functions are called by
 * the server network layer.
 *
 * It is the job of the server network layer to listen on a TCP socket, to
 * accept new connections, to call the server with received messages and to
 * signal closed connections to the server.
 *
 * The network layer is part of the server config. So users can provide a custom
 * implementation if the provided example does not fit their architecture. The
 * network layer is invoked only from the server's main loop. So the network
 * layer does not need to be thread-safe. If the networklayer receives a
 * positive duration for blocking listening, the server's main loop will block
 * until a message is received or the duration times out. */

/* Process a binary message (TCP packet). The message can contain partial
 * chunks. (TCP is a streaming protocol and packets may be split/merge during
 * transport.) After processing, the message is freed with
 * connection->releaseRecvBuffer. */
void UA_EXPORT
UA_Server_processBinaryMessage(UA_Server *server, UA_Connection *connection,
                               UA_ByteString *message);

/* The server internally cleans up the connection and then calls
 * connection->free. */
void UA_EXPORT
UA_Server_removeConnection(UA_Server *server, UA_Connection *connection);

struct UA_ServerNetworkLayer {
    void *handle; /* Internal data */
    UA_String discoveryUrl;

    /* Start listening on the networklayer.
     *
     * @param nl The network layer
     * @return Returns UA_STATUSCODE_GOOD or an error code. */
    UA_StatusCode (*start)(UA_ServerNetworkLayer *nl, const UA_String *customHostname);

    /* Listen for new and closed connections and arriving packets. Calls
     * UA_Server_processBinaryMessage for the arriving packets. Closed
     * connections are picked up here and forwarded to
     * UA_Server_removeConnection where they are cleaned up and freed.
     *
     * @param nl The network layer
     * @param server The server for processing the incoming packets and for
     *               closing connections. 
     * @param timeout The timeout during which an event must arrive in
     *                milliseconds
     * @return A statuscode for the status of the network layer. */
    UA_StatusCode (*listen)(UA_ServerNetworkLayer *nl, UA_Server *server,
                            UA_UInt16 timeout);

    /* Close the network socket and all open connections. Afterwards, the
     * network layer can be safely deleted.
     *
     * @param nl The network layer
     * @param server The server that processes the incoming packets and for
     *               closing connections before deleting them.
     * @return A statuscode for the status of the closing operation. */
    void (*stop)(UA_ServerNetworkLayer *nl, UA_Server *server);

    /* Deletes the network layer context. Call only after stopping. */
    void (*deleteMembers)(UA_ServerNetworkLayer *nl);
};

/**
 * Client Network Layer
 * --------------------
 * The client has only a single connection used for sending and receiving binary
 * messages. */

/* @param localConf the connection config for this client
 * @param endpointUrl to where to connect
 * @param timeout in ms until the connection try times out if remote not reachable
 * @param logger the logger to use */
typedef UA_Connection
(*UA_ConnectClientConnection)(UA_ConnectionConfig localConf, const char *endpointUrl,
                              const UA_UInt32 timeout, UA_Logger logger);

/**
 * Endpoint URL Parser
 * -------------------
 * The endpoint URL parser is generally useful for the implementation of network
 * layer plugins. */

/* Split the given endpoint url into hostname, port and path. All arguments must
 * be non-NULL. EndpointUrls have the form "opc.tcp://hostname:port/path", port
 * and path may be omitted (together with the prefix colon and slash).
 *
 * @param endpointUrl The endpoint URL.
 * @param outHostname Set to the parsed hostname. The string points into the
 *        original endpointUrl, so no memory is allocated. If an IPv6 address is
 *        given, hostname contains e.g. '[2001:0db8:85a3::8a2e:0370:7334]'
 * @param outPort Set to the port of the url or left unchanged.
 * @param outPath Set to the path if one is present in the endpointUrl.
 *        Starting or trailing '/' are NOT included in the path. The string
 *        points into the original endpointUrl, so no memory is allocated.
 * @return Returns UA_STATUSCODE_BADTCPENDPOINTURLINVALID if parsing failed. */
UA_StatusCode UA_EXPORT
UA_parseEndpointUrl(const UA_String *endpointUrl, UA_String *outHostname,
                    UA_UInt16 *outPort, UA_String *outPath);

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_plugin_access_control.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */


#ifdef __cplusplus
extern "C" {
#endif


/**
 * .. _access-control:
 *
 * Access Control Plugin API
 * =========================
 * The access control callback is used to authenticate sessions and grant access
 * rights accordingly. */

struct UA_AccessControl;
typedef struct UA_AccessControl UA_AccessControl;

struct UA_AccessControl {
    void *context;
    void (*deleteMembers)(UA_AccessControl *ac);

    /* Supported login mechanisms. The server endpoints are created from here. */
    size_t userTokenPoliciesSize;
    UA_UserTokenPolicy *userTokenPolicies;
    
    /* Authenticate a session. The session context is attached to the session and
     * later passed into the node-based access control callbacks. */
    UA_StatusCode (*activateSession)(UA_Server *server, UA_AccessControl *ac,
                                     const UA_NodeId *sessionId,
                                     const UA_ExtensionObject *userIdentityToken,
                                     void **sessionContext);

    /* Deauthenticate a session and cleanup */
    void (*closeSession)(UA_Server *server, UA_AccessControl *ac,
                         const UA_NodeId *sessionId, void *sessionContext);

    /* Access control for all nodes*/
    UA_UInt32 (*getUserRightsMask)(UA_Server *server, UA_AccessControl *ac,
                                   const UA_NodeId *sessionId, void *sessionContext,
                                   const UA_NodeId *nodeId, void *nodeContext);

    /* Additional access control for variable nodes */
    UA_Byte (*getUserAccessLevel)(UA_Server *server, UA_AccessControl *ac,
                                  const UA_NodeId *sessionId, void *sessionContext,
                                  const UA_NodeId *nodeId, void *nodeContext);

    /* Additional access control for method nodes */
    UA_Boolean (*getUserExecutable)(UA_Server *server, UA_AccessControl *ac,
                                    const UA_NodeId *sessionId, void *sessionContext,
                                    const UA_NodeId *methodId, void *methodContext);

    /* Additional access control for calling a method node in the context of a
     * specific object */
    UA_Boolean (*getUserExecutableOnObject)(UA_Server *server, UA_AccessControl *ac,
                                            const UA_NodeId *sessionId, void *sessionContext,
                                            const UA_NodeId *methodId, void *methodContext,
                                            const UA_NodeId *objectId, void *objectContext);

    /* Allow adding a node */
    UA_Boolean (*allowAddNode)(UA_Server *server, UA_AccessControl *ac,
                               const UA_NodeId *sessionId, void *sessionContext,
                               const UA_AddNodesItem *item);

    /* Allow adding a reference */
    UA_Boolean (*allowAddReference)(UA_Server *server, UA_AccessControl *ac,
                                    const UA_NodeId *sessionId, void *sessionContext,
                                    const UA_AddReferencesItem *item);

    /* Allow deleting a node */
    UA_Boolean (*allowDeleteNode)(UA_Server *server, UA_AccessControl *ac,
                                  const UA_NodeId *sessionId, void *sessionContext,
                                  const UA_DeleteNodesItem *item);

    /* Allow deleting a reference */
    UA_Boolean (*allowDeleteReference)(UA_Server *server, UA_AccessControl *ac,
                                       const UA_NodeId *sessionId, void *sessionContext,
                                       const UA_DeleteReferencesItem *item);
};

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_plugin_pki.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 */


#ifdef __cplusplus
extern "C" {
#endif


/**
 * Public Key Infrastructure Integration
 * =====================================
 * This file contains interface definitions for integration in a Public Key
 * Infrastructure (PKI). Currently only one plugin interface is defined.
 *
 * Certificate Verification
 * ------------------------
 * This plugin verifies that the origin of the certificate is trusted. It does
 * not assign any access rights/roles to the holder of the certificate.
 *
 * Usually, implementations of the certificate verification plugin provide an
 * initialization method that takes a trust-list and a revocation-list as input.
 * The lifecycle of the plugin is attached to a server or client config. The
 * ``deleteMembers`` method is called automatically when the config is
 * destroyed. */

struct UA_CertificateVerification;
typedef struct UA_CertificateVerification UA_CertificateVerification;

struct UA_CertificateVerification {
    void *context;

    /* Verify the certificate against the configured policies and trust chain. */
    UA_StatusCode (*verifyCertificate)(void *verificationContext,
                                       const UA_ByteString *certificate);

    /* Verify that the certificate has the applicationURI in the subject name. */
    UA_StatusCode (*verifyApplicationURI)(void *verificationContext,
                                          const UA_ByteString *certificate,
                                          const UA_String *applicationURI);

    /* Delete the certificate verification context */
    void (*deleteMembers)(UA_CertificateVerification *cv);
};

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_plugin_securitypolicy.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017-2018 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */


#ifdef __cplusplus
extern "C" {
#endif


extern const UA_ByteString UA_SECURITY_POLICY_NONE_URI;

struct UA_SecurityPolicy;
typedef struct UA_SecurityPolicy UA_SecurityPolicy;

typedef struct {
    UA_String uri;

    /* Verifies the signature of the message using the provided keys in the context.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the channelContext that contains the key to verify
     *                       the supplied message with.
     * @param message the message to which the signature is supposed to belong.
     * @param signature the signature of the message, that should be verified. */
    UA_StatusCode (*verify)(const UA_SecurityPolicy *securityPolicy,
                            void *channelContext, const UA_ByteString *message,
                            const UA_ByteString *signature) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Signs the given message using this policys signing algorithm and the
     * provided keys in the context.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the channelContext that contains the key to sign
     *                       the supplied message with.
     * @param message the message to sign.
     * @param signature an output buffer to which the signature is written. The
     *                  buffer needs to be allocated by the caller. The
     *                  necessary size can be acquired with the signatureSize
     *                  attribute of this module. */
    UA_StatusCode (*sign)(const UA_SecurityPolicy *securityPolicy,
                          void *channelContext, const UA_ByteString *message,
                          UA_ByteString *signature) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Gets the signature size that depends on the local (private) key.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the channelContext that contains the
     *                       certificate/key.
     * @return the size of the local signature. Returns 0 if no local
     *         certificate was set. */
    size_t (*getLocalSignatureSize)(const UA_SecurityPolicy *securityPolicy,
                                    const void *channelContext);

    /* Gets the signature size that depends on the remote (public) key.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the size of the remote signature. Returns 0 if no
     *         remote certificate was set previousely. */
    size_t (*getRemoteSignatureSize)(const UA_SecurityPolicy *securityPolicy,
                                     const void *channelContext);

    /* Gets the local signing key length.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the length of the signing key in bytes. Returns 0 if no length can be found.
     */
    size_t (*getLocalKeyLength)(const UA_SecurityPolicy *securityPolicy,
                                const void *channelContext);

    /* Gets the local signing key length.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the length of the signing key in bytes. Returns 0 if no length can be found.
     */
    size_t (*getRemoteKeyLength)(const UA_SecurityPolicy *securityPolicy,
                                 const void *channelContext);
} UA_SecurityPolicySignatureAlgorithm;

typedef struct {
    UA_String uri;

    /* Encrypt the given data in place using an asymmetric algorithm and keys.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the channelContext which contains information about
     *                       the keys to encrypt data.
     * @param data the data that is encrypted. The encrypted data will overwrite
     *             the data that was supplied. */
    UA_StatusCode (*encrypt)(const UA_SecurityPolicy *securityPolicy,
                             void *channelContext,
                             UA_ByteString *data) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Decrypts the given ciphertext in place using an asymmetric algorithm and
     * key.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the channelContext which contains information about
     *                       the keys needed to decrypt the message.
     * @param data the data to decrypt. The decryption is done in place. */
    UA_StatusCode (*decrypt)(const UA_SecurityPolicy *securityPolicy,
                             void *channelContext,
                             UA_ByteString *data) UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Returns the length of the key used locally to encrypt messages in bits
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the length of the local key. Returns 0 if no
     *         key length is known. */
    size_t (*getLocalKeyLength)(const UA_SecurityPolicy *securityPolicy,
                                const void *channelContext);

    /* Returns the length of the key used remotely to encrypt messages in bits
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the length of the remote key. Returns 0 if no
     *         key length is known. */
    size_t (*getRemoteKeyLength)(const UA_SecurityPolicy *securityPolicy,
                                 const void *channelContext);

    /* Returns the size of encrypted blocks used by the local encryption algorithm.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the size of encrypted blocks in bytes. Returns 0 if no key length is known.
     */
    size_t (*getLocalBlockSize)(const UA_SecurityPolicy *securityPolicy,
                                const void *channelContext);

    /* Returns the size of encrypted blocks used by the remote encryption algorithm.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the size of encrypted blocks in bytes. Returns 0 if no key length is known.
     */
    size_t (*getRemoteBlockSize)(const UA_SecurityPolicy *securityPolicy,
                                 const void *channelContext);

    /* Returns the size of plaintext blocks used by the local encryption algorithm.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the size of plaintext blocks in bytes. Returns 0 if no key length is known.
     */
    size_t (*getLocalPlainTextBlockSize)(const UA_SecurityPolicy *securityPolicy,
                                         const void *channelContext);

    /* Returns the size of plaintext blocks used by the remote encryption algorithm.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param channelContext the context to retrieve data from.
     * @return the size of plaintext blocks in bytes. Returns 0 if no key length is known.
     */
    size_t (*getRemotePlainTextBlockSize)(const UA_SecurityPolicy *securityPolicy,
                                          const void *channelContext);
} UA_SecurityPolicyEncryptionAlgorithm;

typedef struct {
    /*
     * The algorithm used to sign and verify certificates.
     */
    UA_SecurityPolicySignatureAlgorithm signatureAlgorithm;

    /*
     * The algorithm used to encrypt and decrypt messages.
     */
    UA_SecurityPolicyEncryptionAlgorithm encryptionAlgorithm;

} UA_SecurityPolicyCryptoModule;

typedef struct {
    /* Generates a thumbprint for the specified certificate.
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param certificate the certificate to make a thumbprint of.
     * @param thumbprint an output buffer for the resulting thumbprint. Always
     *                   has the length specified in the thumbprintLength in the
     *                   asymmetricModule. */
    UA_StatusCode (*makeCertificateThumbprint)(const UA_SecurityPolicy *securityPolicy,
                                               const UA_ByteString *certificate,
                                               UA_ByteString *thumbprint)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Compares the supplied certificate with the certificate in the endpoit context.
     *
     * @param securityPolicy the policy data that contains the certificate
     *                       to compare to.
     * @param certificateThumbprint the certificate thumbprint to compare to the
     *                              one stored in the context.
     * @return if the thumbprints match UA_STATUSCODE_GOOD is returned. If they
     *         don't match or an error occurred an error code is returned. */
    UA_StatusCode (*compareCertificateThumbprint)(const UA_SecurityPolicy *securityPolicy,
                                                  const UA_ByteString *certificateThumbprint)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    UA_SecurityPolicyCryptoModule cryptoModule;
} UA_SecurityPolicyAsymmetricModule;

typedef struct {
    /* Pseudo random function that is used to generate the symmetric keys.
     *
     * For information on what parameters this function receives in what situation,
     * refer to the OPC UA specification 1.03 Part6 Table 33
     *
     * @param securityPolicy the securityPolicy the function is invoked on.
     * @param secret
     * @param seed
     * @param out an output to write the data to. The length defines the maximum
     *            number of output bytes that are produced. */
    UA_StatusCode (*generateKey)(const UA_SecurityPolicy *securityPolicy,
                                 const UA_ByteString *secret,
                                 const UA_ByteString *seed, UA_ByteString *out)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Random generator for generating nonces.
     *
     * @param securityPolicy the securityPolicy this function is invoked on.
     *                       Example: myPolicy->generateNonce(myPolicy,
     *                       &outBuff);
     * @param out pointer to a buffer to store the nonce in. Needs to be
     *            allocated by the caller. The buffer is filled with random
     *            data. */
    UA_StatusCode (*generateNonce)(const UA_SecurityPolicy *securityPolicy,
                                   UA_ByteString *out)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /*
     * The length of the nonce used in the SecureChannel as specified in the standard.
     */
    size_t secureChannelNonceLength;

    UA_SecurityPolicyCryptoModule cryptoModule;
} UA_SecurityPolicySymmetricModule;

typedef struct {
    /* This method creates a new context data object.
     *
     * The caller needs to call delete on the received object to free allocated
     * memory. Memory is only allocated if the function succeeds so there is no
     * need to manually free the memory pointed to by *channelContext or to
     * call delete in case of failure.
     *
     * @param securityPolicy the policy context of the endpoint that is connected
     *                       to. It will be stored in the channelContext for
     *                       further access by the policy.
     * @param remoteCertificate the remote certificate contains the remote
     *                          asymmetric key. The certificate will be verified
     *                          and then stored in the context so that its
     *                          details may be accessed.
     * @param channelContext the initialized channelContext that is passed to
     *                       functions that work on a context. */
    UA_StatusCode (*newContext)(const UA_SecurityPolicy *securityPolicy,
                                const UA_ByteString *remoteCertificate,
                                void **channelContext)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Deletes the the security context. */
    void (*deleteContext)(void *channelContext);

    /* Sets the local encrypting key in the supplied context.
     *
     * @param channelContext the context to work on.
     * @param key the local encrypting key to store in the context. */
    UA_StatusCode (*setLocalSymEncryptingKey)(void *channelContext,
                                              const UA_ByteString *key)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Sets the local signing key in the supplied context.
     *
     * @param channelContext the context to work on.
     * @param key the local signing key to store in the context. */
    UA_StatusCode (*setLocalSymSigningKey)(void *channelContext,
                                           const UA_ByteString *key)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Sets the local initialization vector in the supplied context.
     *
     * @param channelContext the context to work on.
     * @param iv the local initialization vector to store in the context. */
    UA_StatusCode (*setLocalSymIv)(void *channelContext,
                                   const UA_ByteString *iv)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Sets the remote encrypting key in the supplied context.
     *
     * @param channelContext the context to work on.
     * @param key the remote encrypting key to store in the context. */
    UA_StatusCode (*setRemoteSymEncryptingKey)(void *channelContext,
                                               const UA_ByteString *key)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Sets the remote signing key in the supplied context.
     *
     * @param channelContext the context to work on.
     * @param key the remote signing key to store in the context. */
    UA_StatusCode (*setRemoteSymSigningKey)(void *channelContext,
                                            const UA_ByteString *key)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Sets the remote initialization vector in the supplied context.
     *
     * @param channelContext the context to work on.
     * @param iv the remote initialization vector to store in the context. */
    UA_StatusCode (*setRemoteSymIv)(void *channelContext,
                                    const UA_ByteString *iv)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;

    /* Compares the supplied certificate with the certificate in the channel
     * context.
     *
     * @param channelContext the channel context data that contains the
     *                       certificate to compare to.
     * @param certificate the certificate to compare to the one stored in the context.
     * @return if the certificates match UA_STATUSCODE_GOOD is returned. If they
     *         don't match or an errror occurred an error code is returned. */
    UA_StatusCode (*compareCertificate)(const void *channelContext,
                                        const UA_ByteString *certificate)
    UA_FUNC_ATTR_WARN_UNUSED_RESULT;
} UA_SecurityPolicyChannelModule;

struct UA_SecurityPolicy {
    /* Additional data */
    void *policyContext;

    /* The policy uri that identifies the implemented algorithms */
    UA_ByteString policyUri;

    /* The local certificate is specific for each SecurityPolicy since it
     * depends on the used key length. */
    UA_ByteString localCertificate;

    /* Function pointers grouped into modules */
    UA_SecurityPolicyAsymmetricModule asymmetricModule;
    UA_SecurityPolicySymmetricModule symmetricModule;
    UA_SecurityPolicySignatureAlgorithm certificateSigningAlgorithm;
    UA_SecurityPolicyChannelModule channelModule;
    UA_CertificateVerification *certificateVerification;

    UA_Logger logger;

    /* Deletes the dynamic content of the policy */
    void (*deleteMembers)(UA_SecurityPolicy *policy);
};

typedef struct {
    UA_SecurityPolicy securityPolicy;
    UA_EndpointDescription endpointDescription;
} UA_Endpoint;

/* Gets the number of bytes that are needed by the encryption function in
 * addition to the length of the plaintext message. This is needed, since
 * most RSA encryption methods have their own padding mechanism included.
 * This makes the encrypted message larger than the plainText, so we need to
 * have enough room in the buffer for the overhead.
 *
 * @param securityPolicy the algorithms to use.
 * @param channelContext the retrieve data from.
 * @param maxEncryptionLength the maximum number of bytes that the data to
 *                            encrypt can be. */
size_t
UA_SecurityPolicy_getRemoteAsymEncryptionBufferLengthOverhead(const UA_SecurityPolicy *securityPolicy,
                                                              const void *channelContext,
                                                              size_t maxEncryptionLength);

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_plugin_nodestore.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2017 (c) Julian Grothoff
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */


/* !!! Warning !!!
 *
 * If you are not developing a nodestore plugin, then you should not work with
 * the definitions from this file directly. The underlying node structures are
 * not meant to be used directly by end users. Please use the public server API
 * / OPC UA services to interact with the information model. */

#ifdef __cplusplus
extern "C" {
#endif


/**
 * .. _information-modelling:
 *
 * Information Modelling
 * =====================
 *
 * Information modelling in OPC UA combines concepts from object-orientation and
 * semantic modelling. At the core, an OPC UA information model is a graph made
 * up of
 *
 * - Nodes: There are eight possible Node types (variable, object, method, ...)
 * - References: Typed and directed relations between two nodes
 *
 * Every node is identified by a unique (within the server) :ref:`nodeid`.
 * Reference are triples of the form ``(source-nodeid, referencetype-nodeid,
 * target-nodeid)``. An example reference between nodes is a
 * ``hasTypeDefinition`` reference between a Variable and its VariableType. Some
 * ReferenceTypes are *hierarchic* and must not form *directed loops*. See the
 * section on :ref:`ReferenceTypes <referencetypenode>` for more details on
 * possible references and their semantics.
 *
 * **Warning!!** The structures defined in this section are only relevant for
 * the developers of custom Nodestores. The interaction with the information
 * model is possible only via the OPC UA :ref:`services`. So the following
 * sections are purely informational so that users may have a clear mental
 * model of the underlying representation.
 *
 * Base Node Attributes
 * --------------------
 *
 * Nodes contain attributes according to their node type. The base node
 * attributes are common to all node types. In the OPC UA :ref:`services`,
 * attributes are referred to via the :ref:`nodeid` of the containing node and
 * an integer :ref:`attribute-id`.
 *
 * Internally, open62541 uses ``UA_Node`` in places where the exact node type is
 * not known or not important. The ``nodeClass`` attribute is used to ensure the
 * correctness of casting from ``UA_Node`` to a specific node type. */

/* List of reference targets with the same reference type and direction */
typedef struct {
    UA_NodeId referenceTypeId;
    UA_Boolean isInverse;
    size_t targetIdsSize;
    UA_ExpandedNodeId *targetIds;
} UA_NodeReferenceKind;

#define UA_NODE_BASEATTRIBUTES                  \
    UA_NodeId nodeId;                           \
    UA_NodeClass nodeClass;                     \
    UA_QualifiedName browseName;                \
    UA_LocalizedText displayName;               \
    UA_LocalizedText description;               \
    UA_UInt32 writeMask;                        \
    size_t referencesSize;                      \
    UA_NodeReferenceKind *references;           \
                                                \
    /* Members specific to open62541 */         \
    void *context;

typedef struct {
    UA_NODE_BASEATTRIBUTES
} UA_Node;

/**
 * VariableNode
 * ------------
 *
 * Variables store values in a :ref:`datavalue` together with
 * metadata for introspection. Most notably, the attributes data type, value
 * rank and array dimensions constrain the possible values the variable can take
 * on.
 *
 * Variables come in two flavours: properties and datavariables. Properties are
 * related to a parent with a ``hasProperty`` reference and may not have child
 * nodes themselves. Datavariables may contain properties (``hasProperty``) and
 * also datavariables (``hasComponents``).
 *
 * All variables are instances of some :ref:`variabletypenode` in return
 * constraining the possible data type, value rank and array dimensions
 * attributes.
 *
 * Data Type
 * ^^^^^^^^^
 *
 * The (scalar) data type of the variable is constrained to be of a specific
 * type or one of its children in the type hierarchy. The data type is given as
 * a NodeId pointing to a :ref:`datatypenode` in the type hierarchy. See the
 * Section :ref:`datatypenode` for more details.
 *
 * If the data type attribute points to ``UInt32``, then the value attribute
 * must be of that exact type since ``UInt32`` does not have children in the
 * type hierarchy. If the data type attribute points ``Number``, then the type
 * of the value attribute may still be ``UInt32``, but also ``Float`` or
 * ``Byte``.
 *
 * Consistency between the data type attribute in the variable and its
 * :ref:`VariableTypeNode` is ensured.
 *
 * Value Rank
 * ^^^^^^^^^^
 *
 * This attribute indicates whether the value attribute of the variable is an
 * array and how many dimensions the array has. It may have the following
 * values:
 *
 * - ``n >= 1``: the value is an array with the specified number of dimensions
 * - ``n =  0``: the value is an array with one or more dimensions
 * - ``n = -1``: the value is a scalar
 * - ``n = -2``: the value can be a scalar or an array with any number of dimensions
 * - ``n = -3``: the value can be a scalar or a one dimensional array
 *
 * Consistency between the value rank attribute in the variable and its
 * :ref:`variabletypenode` is ensured.
 *
 * Array Dimensions
 * ^^^^^^^^^^^^^^^^
 *
 * If the value rank permits the value to be a (multi-dimensional) array, the
 * exact length in each dimensions can be further constrained with this
 * attribute.
 *
 * - For positive lengths, the variable value is guaranteed to be of the same
 *   length in this dimension.
 * - The dimension length zero is a wildcard and the actual value may have any
 *   length in this dimension.
 *
 * Consistency between the array dimensions attribute in the variable and its
 * :ref:`variabletypenode` is ensured. */

/* Indicates whether a variable contains data inline or whether it points to an
 * external data source */
typedef enum {
    UA_VALUESOURCE_DATA,
    UA_VALUESOURCE_DATASOURCE
} UA_ValueSource;

#define UA_NODE_VARIABLEATTRIBUTES                                      \
    /* Constraints on possible values */                                \
    UA_NodeId dataType;                                                 \
    UA_Int32 valueRank;                                                 \
    size_t arrayDimensionsSize;                                         \
    UA_UInt32 *arrayDimensions;                                         \
                                                                        \
    /* The current value */                                             \
    UA_ValueSource valueSource;                                         \
    union {                                                             \
        struct {                                                        \
            UA_DataValue value;                                         \
            UA_ValueCallback callback;                                  \
        } data;                                                         \
        UA_DataSource dataSource;                                       \
    } value;

typedef struct {
    UA_NODE_BASEATTRIBUTES
    UA_NODE_VARIABLEATTRIBUTES
    UA_Byte accessLevel;
    UA_Double minimumSamplingInterval;
    UA_Boolean historizing; /* currently unsupported */
} UA_VariableNode;

/**
 * .. _variabletypenode:
 *
 * VariableTypeNode
 * ----------------
 *
 * VariableTypes are used to provide type definitions for variables.
 * VariableTypes constrain the data type, value rank and array dimensions
 * attributes of variable instances. Furthermore, instantiating from a specific
 * variable type may provide semantic information. For example, an instance from
 * ``MotorTemperatureVariableType`` is more meaningful than a float variable
 * instantiated from ``BaseDataVariable``. */

typedef struct {
    UA_NODE_BASEATTRIBUTES
    UA_NODE_VARIABLEATTRIBUTES
    UA_Boolean isAbstract;

    /* Members specific to open62541 */
    UA_NodeTypeLifecycle lifecycle;
} UA_VariableTypeNode;

/**
 * .. _methodnode:
 *
 * MethodNode
 * ----------
 *
 * Methods define callable functions and are invoked using the :ref:`Call
 * <method-services>` service. MethodNodes may have special properties (variable
 * childen with a ``hasProperty`` reference) with the :ref:`qualifiedname` ``(0,
 * "InputArguments")`` and ``(0, "OutputArguments")``. The input and output
 * arguments are both described via an array of ``UA_Argument``. While the Call
 * service uses a generic array of :ref:`variant` for input and output, the
 * actual argument values are checked to match the signature of the MethodNode.
 *
 * Note that the same MethodNode may be referenced from several objects (and
 * object types). For this, the NodeId of the method *and of the object
 * providing context* is part of a Call request message. */

typedef struct {
    UA_NODE_BASEATTRIBUTES
    UA_Boolean executable;

    /* Members specific to open62541 */
    UA_MethodCallback method;
} UA_MethodNode;

/**
 * ObjectNode
 * ----------
 *
 * Objects are used to represent systems, system components, real-world objects
 * and software objects. Objects are instances of an :ref:`object
 * type<objecttypenode>` and may contain variables, methods and further
 * objects. */

typedef struct {
    UA_NODE_BASEATTRIBUTES
    UA_Byte eventNotifier;
} UA_ObjectNode;

/**
 * .. _objecttypenode:
 *
 * ObjectTypeNode
 * --------------
 *
 * ObjectTypes provide definitions for Objects. Abstract objects cannot be
 * instantiated. See :ref:`node-lifecycle` for the use of constructor and
 * destructor callbacks. */

typedef struct {
    UA_NODE_BASEATTRIBUTES
    UA_Boolean isAbstract;

    /* Members specific to open62541 */
    UA_NodeTypeLifecycle lifecycle;
} UA_ObjectTypeNode;

/**
 * .. _referencetypenode:
 *
 * ReferenceTypeNode
 * -----------------
 *
 * Each reference between two nodes is typed with a ReferenceType that gives
 * meaning to the relation. The OPC UA standard defines a set of ReferenceTypes
 * as a mandatory part of OPC UA information models.
 *
 * - Abstract ReferenceTypes cannot be used in actual references and are only
 *   used to structure the ReferenceTypes hierarchy
 * - Symmetric references have the same meaning from the perspective of the
 *   source and target node
 *
 * The figure below shows the hierarchy of the standard ReferenceTypes (arrows
 * indicate a ``hasSubType`` relation). Refer to Part 3 of the OPC UA
 * specification for the full semantics of each ReferenceType.
 *
 * .. graphviz::
 *
 *    digraph tree {
 *
 *    node [height=0, shape=box, fillcolor="#E5E5E5", concentrate=true]
 *
 *    references [label="References\n(Abstract, Symmetric)"]
 *    hierarchical_references [label="HierarchicalReferences\n(Abstract)"]
 *    references -> hierarchical_references
 *
 *    nonhierarchical_references [label="NonHierarchicalReferences\n(Abstract, Symmetric)"]
 *    references -> nonhierarchical_references
 *
 *    haschild [label="HasChild\n(Abstract)"]
 *    hierarchical_references -> haschild
 *
 *    aggregates [label="Aggregates\n(Abstract)"]
 *    haschild -> aggregates
 *
 *    organizes [label="Organizes"]
 *    hierarchical_references -> organizes
 *
 *    hascomponent [label="HasComponent"]
 *    aggregates -> hascomponent
 *
 *    hasorderedcomponent [label="HasOrderedComponent"]
 *    hascomponent -> hasorderedcomponent
 *
 *    hasproperty [label="HasProperty"]
 *    aggregates -> hasproperty
 *
 *    hassubtype [label="HasSubtype"]
 *    haschild -> hassubtype
 *
 *    hasmodellingrule [label="HasModellingRule"]
 *    nonhierarchical_references -> hasmodellingrule
 *
 *    hastypedefinition [label="HasTypeDefinition"]
 *    nonhierarchical_references -> hastypedefinition
 *
 *    hasencoding [label="HasEncoding"]
 *    nonhierarchical_references -> hasencoding
 *
 *    hasdescription [label="HasDescription"]
 *    nonhierarchical_references -> hasdescription
 *
 *    haseventsource [label="HasEventSource"]
 *    hierarchical_references -> haseventsource
 *
 *    hasnotifier [label="HasNotifier"]
 *    hierarchical_references -> hasnotifier
 *
 *    generatesevent [label="GeneratesEvent"]
 *    nonhierarchical_references -> generatesevent
 *
 *    alwaysgeneratesevent [label="AlwaysGeneratesEvent"]
 *    generatesevent -> alwaysgeneratesevent
 *
 *    {rank=same hierarchical_references nonhierarchical_references}
 *    {rank=same generatesevent haseventsource hasmodellingrule
 *               hasencoding hassubtype}
 *    {rank=same alwaysgeneratesevent hasproperty}
 *
 *    }
 *
 * The ReferenceType hierarchy can be extended with user-defined ReferenceTypes.
 * Many Companion Specifications for OPC UA define new ReferenceTypes to be used
 * in their domain of interest.
 *
 * For the following example of custom ReferenceTypes, we attempt to model the
 * structure of a technical system. For this, we introduce two custom
 * ReferenceTypes. First, the hierarchical ``contains`` ReferenceType indicates
 * that a system (represented by an OPC UA object) contains a component (or
 * subsystem). This gives rise to a tree-structure of containment relations. For
 * example, the motor (object) is contained in the car and the crankshaft is
 * contained in the motor. Second, the symmetric ``connectedTo`` ReferenceType
 * indicates that two components are connected. For example, the motor's
 * crankshaft is connected to the gear box. Connections are independent of the
 * containment hierarchy and can induce a general graph-structure. Further
 * subtypes of ``connectedTo`` could be used to differentiate between physical,
 * electrical and information related connections. A client can then learn the
 * layout of a (physical) system represented in an OPC UA information model
 * based on a common understanding of just two custom reference types. */

typedef struct {
    UA_NODE_BASEATTRIBUTES
    UA_Boolean isAbstract;
    UA_Boolean symmetric;
    UA_LocalizedText inverseName;
} UA_ReferenceTypeNode;

/**
 * .. _datatypenode:
 *
 * DataTypeNode
 * ------------
 *
 * DataTypes represent simple and structured data types. DataTypes may contain
 * arrays. But they always describe the structure of a single instance. In
 * open62541, DataTypeNodes in the information model hierarchy are matched to
 * ``UA_DataType`` type descriptions for :ref:`generic-types` via their NodeId.
 *
 * Abstract DataTypes (e.g. ``Number``) cannot be the type of actual values.
 * They are used to constrain values to possible child DataTypes (e.g.
 * ``UInt32``). */

typedef struct {
    UA_NODE_BASEATTRIBUTES
    UA_Boolean isAbstract;
} UA_DataTypeNode;

/**
 * ViewNode
 * --------
 *
 * Each View defines a subset of the Nodes in the AddressSpace. Views can be
 * used when browsing an information model to focus on a subset of nodes and
 * references only. ViewNodes can be created and be interacted with. But their
 * use in the :ref:`Browse<view-services>` service is currently unsupported in
 * open62541. */

typedef struct {
    UA_NODE_BASEATTRIBUTES
    UA_Byte eventNotifier;
    UA_Boolean containsNoLoops;
} UA_ViewNode;

/**
 * Nodestore Plugin API
 * --------------------
 * The following definitions are used for implementing custom node storage
 * backends. **Most users will want to use the default nodestore and don't need
 * to work with the nodestore API**.
 *
 * Outside of custom nodestore implementations, users should not manually edit
 * nodes. Please use the OPC UA services for that. Otherwise, all consistency
 * checks are omitted. This can crash the application eventually. */

typedef void (*UA_NodestoreVisitor)(void *visitorContext, const UA_Node *node);

typedef struct {
    /* Nodestore context and lifecycle */
    void *context;
    void (*deleteNodestore)(void *nodestoreContext);

    /* For non-multithreaded access, some nodestores allow that nodes are edited
     * without a copy/replace. This is not possible when the node is only an
     * intermediate representation and stored e.g. in a database backend. */
    UA_Boolean inPlaceEditAllowed;

    /* The following definitions are used to create empty nodes of the different
     * node types. The memory is managed by the nodestore. Therefore, the node
     * has to be removed via a special deleteNode function. (If the new node is
     * not added to the nodestore.) */
    UA_Node * (*newNode)(void *nodestoreContext, UA_NodeClass nodeClass);

    void (*deleteNode)(void *nodestoreContext, UA_Node *node);

    /* ``Get`` returns a pointer to an immutable node. ``Release`` indicates
     * that the pointer is no longer accessed afterwards. */

    const UA_Node * (*getNode)(void *nodestoreContext, const UA_NodeId *nodeId);

    void (*releaseNode)(void *nodestoreContext, const UA_Node *node);

    /* Returns an editable copy of a node (needs to be deleted with the
     * deleteNode function or inserted / replaced into the nodestore). */
    UA_StatusCode (*getNodeCopy)(void *nodestoreContext, const UA_NodeId *nodeId,
                                 UA_Node **outNode);

    /* Inserts a new node into the nodestore. If the NodeId is zero, then a
     * fresh numeric NodeId is assigned. If insertion fails, the node is
     * deleted. */
    UA_StatusCode (*insertNode)(void *nodestoreContext, UA_Node *node,
                                UA_NodeId *addedNodeId);

    /* To replace a node, get an editable copy of the node, edit and replace
     * with this function. If the node was already replaced since the copy was
     * made, UA_STATUSCODE_BADINTERNALERROR is returned. If the NodeId is not
     * found, UA_STATUSCODE_BADNODEIDUNKNOWN is returned. In both error cases,
     * the editable node is deleted. */
    UA_StatusCode (*replaceNode)(void *nodestoreContext, UA_Node *node);

    /* Removes a node from the nodestore. */
    UA_StatusCode (*removeNode)(void *nodestoreContext, const UA_NodeId *nodeId);

    /* Execute a callback for every node in the nodestore. */
    void (*iterate)(void *nodestoreContext, void* visitorContext,
                    UA_NodestoreVisitor visitor);
} UA_Nodestore;

/**
 * The following methods specialize internally for the different node classes
 * (distinguished by the nodeClass member) */

/* Attributes must be of a matching type (VariableAttributes, ObjectAttributes,
 * and so on). The attributes are copied. Note that the attributes structs do
 * not contain NodeId, NodeClass and BrowseName. The NodeClass of the node needs
 * to be correctly set before calling this method. UA_Node_deleteMembers is
 * called on the node when an error occurs internally. */
UA_StatusCode UA_EXPORT
UA_Node_setAttributes(UA_Node *node, const void *attributes,
                      const UA_DataType *attributeType);

/* Reset the destination node and copy the content of the source */
UA_StatusCode UA_EXPORT
UA_Node_copy(const UA_Node *src, UA_Node *dst);

/* Allocate new node and copy the values from src */
UA_EXPORT UA_Node *
UA_Node_copy_alloc(const UA_Node *src);

/* Add a single reference to the node */
UA_StatusCode UA_EXPORT
UA_Node_addReference(UA_Node *node, const UA_AddReferencesItem *item);

/* Delete a single reference from the node */
UA_StatusCode UA_EXPORT
UA_Node_deleteReference(UA_Node *node, const UA_DeleteReferencesItem *item);

/* Delete all references of the node */
void UA_EXPORT
UA_Node_deleteReferences(UA_Node *node);

/* Remove all malloc'ed members of the node */
void UA_EXPORT
UA_Node_deleteMembers(UA_Node *node);

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_server_config.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Henrik Norrman
 */


#ifdef __cplusplus
extern "C" {
#endif


/**
 * .. _server-configuration:
 *
 * Server Configuration
 * --------------------

 * The configuration structure is passed to the server during initialization.
 * The server expects that the configuration is not modified during runtime.
 * Currently, only one server can use a configuration at a time. During
 * shutdown, the server will clean up the parts of the configuration that are
 * modified at runtime through the provided API.
 *
 * Examples for configurations are provided in the ``/plugins`` folder.
 * The usual usage is as follows:
 *
 * 1. Create a server configuration with default settings as a starting point
 * 2. Modifiy the configuration, e.g. by adding a server certificate
 * 3. Instantiate a server with it
 * 4. After shutdown of the server, clean up the configuration (free memory)
 *
 * The :ref:`tutorials` provide a good starting point for this. */

typedef struct {
    UA_UInt32 min;
    UA_UInt32 max;
} UA_UInt32Range;

typedef struct {
    UA_Duration min;
    UA_Duration max;
} UA_DurationRange;

struct UA_ServerConfig {
    UA_UInt16 nThreads; /* only if multithreading is enabled */
    UA_Logger logger;

    /* Server Description */
    UA_BuildInfo buildInfo;
    UA_ApplicationDescription applicationDescription;
    UA_ByteString serverCertificate;

    /* MDNS Discovery */
#ifdef UA_ENABLE_DISCOVERY
    UA_String mdnsServerName;
    size_t serverCapabilitiesSize;
    UA_String *serverCapabilities;
#endif

    /* Custom DataTypes */
    size_t customDataTypesSize;
    UA_DataType *customDataTypes;
    /**
     * .. note:: See the section on :ref:`generic-types`. Examples for working
     *    with custom data types are provided in
     *    ``/examples/custom_datatype/``. */

    /* Nodestore */
    UA_Nodestore nodestore;

    /* Networking */
    size_t networkLayersSize;
    UA_ServerNetworkLayer *networkLayers;
    UA_String customHostname;

    /* Available endpoints */
    size_t endpointsSize;
    UA_Endpoint *endpoints;

    /* Node Lifecycle callbacks */
    UA_GlobalNodeLifecycle nodeLifecycle;
    /**
     * .. note:: See the section for :ref:`node lifecycle
     *    handling<node-lifecycle>`. */

    /* Access Control */
    UA_AccessControl accessControl;
    /**
     * .. note:: See the section for :ref:`access-control
     *    handling<access-control>`. */

    /* Certificate Verification */
    UA_CertificateVerification certificateVerification;

    /* Limits for SecureChannels */
    UA_UInt16 maxSecureChannels;
    UA_UInt32 maxSecurityTokenLifetime; /* in ms */

    /* Limits for Sessions */
    UA_UInt16 maxSessions;
    UA_Double maxSessionTimeout; /* in ms */

    /* Operation limits */
    UA_UInt32 maxNodesPerRead;
    UA_UInt32 maxNodesPerWrite;
    UA_UInt32 maxNodesPerMethodCall;
    UA_UInt32 maxNodesPerBrowse;
    UA_UInt32 maxNodesPerRegisterNodes;
    UA_UInt32 maxNodesPerTranslateBrowsePathsToNodeIds;
    UA_UInt32 maxNodesPerNodeManagement;
    UA_UInt32 maxMonitoredItemsPerCall;

    /* Limits for Requests */
    UA_UInt32 maxReferencesPerNode;

    /* Limits for Subscriptions */
    UA_UInt32 maxSubscriptionsPerSession;
    UA_DurationRange publishingIntervalLimits; /* in ms (must not be less than 5) */
    UA_UInt32Range lifeTimeCountLimits;
    UA_UInt32Range keepAliveCountLimits;
    UA_UInt32 maxNotificationsPerPublish;
    UA_UInt32 maxRetransmissionQueueSize; /* 0 -> unlimited size */

    /* Limits for MonitoredItems */
    UA_UInt32 maxMonitoredItemsPerSubscription;
    UA_DurationRange samplingIntervalLimits; /* in ms (must not be less than 5) */
    UA_UInt32Range queueSizeLimits; /* Negotiated with the client */

    /* Limits for PublishRequests */
    UA_UInt32 maxPublishReqPerSession;

    /* Discovery */
#ifdef UA_ENABLE_DISCOVERY
    /* Timeout in seconds when to automatically remove a registered server from
     * the list, if it doesn't re-register within the given time frame. A value
     * of 0 disables automatic removal. Default is 60 Minutes (60*60). Must be
     * bigger than 10 seconds, because cleanup is only triggered approximately
     * ervery 10 seconds. The server will still be removed depending on the
     * state of the semaphore file. */
    UA_UInt32 discoveryCleanupTimeout;
#endif
};

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_client_config.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2018 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2018 (c) Thomas Stalder, Blue Time Concept SA
 */

#ifndef UA_CLIENT_CONFIG_H
#define UA_CLIENT_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif


/**
 * .. _client-config:
 *
 * Client Configuration
 * --------------------
 *
 * The client configuration is used for setting connection parameters and
 * additional settings used by the client.
 * The configuration should not be modified after it is passed to a client.
 * Currently, only one client can use a configuration at a time.
 *
 * Examples for configurations are provided in the ``/plugins`` folder.
 * The usual usage is as follows:
 *
 * 1. Create a client configuration with default settings as a starting point
 * 2. Modifiy the configuration, e.g. modifying the timeout
 * 3. Instantiate a client with it
 * 4. After shutdown of the client, clean up the configuration (free memory)
 *
 * The :ref:`tutorials` provide a good starting point for this. */

typedef enum {
    UA_CLIENTSTATE_DISCONNECTED,        /* The client is disconnected */
    UA_CLIENTSTATE_CONNECTED,           /* A TCP connection to the server is open */
    UA_CLIENTSTATE_SECURECHANNEL,       /* A SecureChannel to the server is open */
    UA_CLIENTSTATE_SESSION,             /* A session with the server is open */
    UA_CLIENTSTATE_SESSION_RENEWED      /* A session with the server is open (renewed) */
} UA_ClientState;


struct UA_Client;
typedef struct UA_Client UA_Client;

/**
 * Client Lifecycle callback
 * ^^^^^^^^^^^^^^^^^^^^^^^^^ */

typedef void (*UA_ClientStateCallback)(UA_Client *client, UA_ClientState clientState);

/**
 * Subscription Inactivity callback
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */

#ifdef UA_ENABLE_SUBSCRIPTIONS
typedef void (*UA_SubscriptionInactivityCallback)(UA_Client *client, UA_UInt32 subscriptionId, void *subContext);
#endif

/**
 * Inactivity callback
 * ^^^^^^^^^^^^^^^^^^^ */

typedef void (*UA_InactivityCallback)(UA_Client *client);

/**
 * Client Configuration Data
 * ^^^^^^^^^^^^^^^^^^^^^^^^^ */

typedef struct UA_ClientConfig {
    UA_UInt32 timeout;               /* ASync + Sync response timeout in ms */
    UA_UInt32 secureChannelLifeTime; /* Lifetime in ms (then the channel needs
                                        to be renewed) */
    UA_Logger logger;
    UA_ConnectionConfig localConnectionConfig;
    UA_ConnectClientConnection connectionFunc;

    /* Custom DataTypes */
    size_t customDataTypesSize;
    const UA_DataType *customDataTypes;

    /* Callback function */
    UA_ClientStateCallback stateCallback;
#ifdef UA_ENABLE_SUBSCRIPTIONS
    /* When outStandingPublishRequests is greater than 0,
     * the server automatically create publishRequest when
     * UA_Client_runAsync is called. If the client don't receive
     * a publishResponse after :
     *     (sub->publishingInterval * sub->maxKeepAliveCount) +
     *     client->config.timeout)
     * then, the client call subscriptionInactivityCallback
     * The connection can be closed, this in an attempt to
     * recreate a healthy connection. */
    UA_SubscriptionInactivityCallback subscriptionInactivityCallback;
#endif

    /* When connectivityCheckInterval is greater than 0,
     * every connectivityCheckInterval (in ms), a async read request
     * is performed on the server. inactivityCallback is called
     * when the client receive no response for this read request
     * The connection can be closed, this in an attempt to
     * recreate a healthy connection. */
    UA_InactivityCallback inactivityCallback;

    void *clientContext;

#ifdef UA_ENABLE_SUBSCRIPTIONS
    /* number of PublishResponse standing in the sever
     * 0 = background task disabled                    */
    UA_UInt16 outStandingPublishRequests;
#endif
    /* connectivity check interval in ms
     * 0 = background task disabled */
    UA_UInt32 connectivityCheckInterval;
} UA_ClientConfig;


/* Get the client configuration from the configuration plugin. Used by the
 * server when it needs client functionality to register to a discovery server
 * or when the server needs to create a client for other purposes
 *
 * @return The client configuration structure */
UA_ClientConfig UA_EXPORT
UA_Server_getClientConfig(void);

#ifdef __cplusplus
}
#endif


#endif /* UA_CLIENT_CONFIG_H */

/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_client.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2015-2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2015-2016 (c) Sten Grüner
 *    Copyright 2015-2016 (c) Chris Iatrou
 *    Copyright 2015-2017 (c) Florian Palm
 *    Copyright 2015 (c) Holger Jeromin
 *    Copyright 2015 (c) Oleksiy Vasylyev
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2018 (c) Thomas Stalder, Blue Time Concept SA
 */


#ifdef __cplusplus
extern "C" {
#endif


/**
 * .. _client:
 *
 * Client
 * ======
 *
 * The client implementation allows remote access to all OPC UA services. For
 * convenience, some functionality has been wrapped in :ref:`high-level
 * abstractions <client-highlevel>`.
 *
 * **However**: At this time, the client does not yet contain its own thread or
 * event-driven main-loop. So the client will not perform any actions
 * automatically in the background. This is especially relevant for
 * subscriptions. The user will have to periodically call
 * `UA_Client_Subscriptions_manuallySendPublishRequest`. See also :ref:`here
 * <client-subscriptions>`.
 *
 *
 * .. include:: client_config.rst
 *
 * Client Lifecycle
 * ---------------- */

/* Create a new client */
UA_Client UA_EXPORT *
UA_Client_new(UA_ClientConfig config);

/* Get the client connection status */
UA_ClientState UA_EXPORT
UA_Client_getState(UA_Client *client);

/* Get the client context */
void UA_EXPORT *
UA_Client_getContext(UA_Client *client);

/* Reset a client */
void UA_EXPORT
UA_Client_reset(UA_Client *client);

/* Delete a client */
void UA_EXPORT
UA_Client_delete(UA_Client *client);

/**
 * Connect to a Server
 * ------------------- */

/* Connect to the server
 *
 * @param client to use
 * @param endpointURL to connect (for example "opc.tcp://localhost:4840")
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_Client_connect(UA_Client *client, const char *endpointUrl);

/* Connect to the selected server with the given username and password
 *
 * @param client to use
 * @param endpointURL to connect (for example "opc.tcp://localhost:4840")
 * @param username
 * @param password
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_Client_connect_username(UA_Client *client, const char *endpointUrl,
                           const char *username, const char *password);

/* Disconnect and close a connection to the selected server */
UA_StatusCode UA_EXPORT
UA_Client_disconnect(UA_Client *client);

/* Close a connection to the selected server */
UA_StatusCode UA_EXPORT
UA_Client_close(UA_Client *client);

/* Renew the underlying secure channel */
UA_StatusCode UA_EXPORT
UA_Client_manuallyRenewSecureChannel(UA_Client *client);

/**
 * Discovery
 * --------- */

/* Gets a list of endpoints of a server
 *
 * @param client to use. Must be connected to the same endpoint given in
 *        serverUrl or otherwise in disconnected state.
 * @param serverUrl url to connect (for example "opc.tcp://localhost:4840")
 * @param endpointDescriptionsSize size of the array of endpoint descriptions
 * @param endpointDescriptions array of endpoint descriptions that is allocated
 *        by the function (you need to free manually)
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_Client_getEndpoints(UA_Client *client, const char *serverUrl,
                       size_t* endpointDescriptionsSize,
                       UA_EndpointDescription** endpointDescriptions);

/* Gets a list of all registered servers at the given server.
 *
 * You can pass an optional filter for serverUris. If the given server is not registered,
 * an empty array will be returned. If the server is registered, only that application
 * description will be returned.
 *
 * Additionally you can optionally indicate which locale you want for the server name
 * in the returned application description. The array indicates the order of preference.
 * A server may have localized names.
 *
 * @param client to use. Must be connected to the same endpoint given in
 *        serverUrl or otherwise in disconnected state.
 * @param serverUrl url to connect (for example "opc.tcp://localhost:4840")
 * @param serverUrisSize Optional filter for specific server uris
 * @param serverUris Optional filter for specific server uris
 * @param localeIdsSize Optional indication which locale you prefer
 * @param localeIds Optional indication which locale you prefer
 * @param registeredServersSize size of returned array, i.e., number of found/registered servers
 * @param registeredServers array containing found/registered servers
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_Client_findServers(UA_Client *client, const char *serverUrl,
                      size_t serverUrisSize, UA_String *serverUris,
                      size_t localeIdsSize, UA_String *localeIds,
                      size_t *registeredServersSize,
                      UA_ApplicationDescription **registeredServers);

/* Get a list of all known server in the network. Only supported by LDS servers.
 *
 * @param client to use. Must be connected to the same endpoint given in
 * serverUrl or otherwise in disconnected state.
 * @param serverUrl url to connect (for example "opc.tcp://localhost:4840")
 * @param startingRecordId optional. Only return the records with an ID higher
 *        or equal the given. Can be used for pagination to only get a subset of
 *        the full list
 * @param maxRecordsToReturn optional. Only return this number of records

 * @param serverCapabilityFilterSize optional. Filter the returned list to only
 *        get servers with given capabilities, e.g. "LDS"
 * @param serverCapabilityFilter optional. Filter the returned list to only get
 *        servers with given capabilities, e.g. "LDS"
 * @param serverOnNetworkSize size of returned array, i.e., number of
 *        known/registered servers
 * @param serverOnNetwork array containing known/registered servers
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_Client_findServersOnNetwork(UA_Client *client, const char *serverUrl,
                               UA_UInt32 startingRecordId, UA_UInt32 maxRecordsToReturn,
                               size_t serverCapabilityFilterSize, UA_String *serverCapabilityFilter,
                               size_t *serverOnNetworkSize, UA_ServerOnNetwork **serverOnNetwork);

/**
 * .. _client-services:
 *
 * Services
 * --------
 *
 * The raw OPC UA services are exposed to the client. But most of them time, it
 * is better to use the convenience functions from ``ua_client_highlevel.h``
 * that wrap the raw services. */
/* Don't use this function. Use the type versions below instead. */
void UA_EXPORT
__UA_Client_Service(UA_Client *client, const void *request,
                    const UA_DataType *requestType, void *response,
                    const UA_DataType *responseType);

/*
 * Attribute Service Set
 * ^^^^^^^^^^^^^^^^^^^^^ */
static UA_INLINE UA_ReadResponse
UA_Client_Service_read(UA_Client *client, const UA_ReadRequest request) {
    UA_ReadResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_READREQUEST],
                        &response, &UA_TYPES[UA_TYPES_READRESPONSE]);
    return response;
}

static UA_INLINE UA_WriteResponse
UA_Client_Service_write(UA_Client *client, const UA_WriteRequest request) {
    UA_WriteResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_WRITEREQUEST],
                        &response, &UA_TYPES[UA_TYPES_WRITERESPONSE]);
    return response;
}

/*
 * Method Service Set
 * ^^^^^^^^^^^^^^^^^^ */
#ifdef UA_ENABLE_METHODCALLS
static UA_INLINE UA_CallResponse
UA_Client_Service_call(UA_Client *client, const UA_CallRequest request) {
    UA_CallResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_CALLREQUEST],
                        &response, &UA_TYPES[UA_TYPES_CALLRESPONSE]);
    return response;
}
#endif

/*
 * NodeManagement Service Set
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^ */
static UA_INLINE UA_AddNodesResponse
UA_Client_Service_addNodes(UA_Client *client, const UA_AddNodesRequest request) {
    UA_AddNodesResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_ADDNODESREQUEST],
                        &response, &UA_TYPES[UA_TYPES_ADDNODESRESPONSE]);
    return response;
}

static UA_INLINE UA_AddReferencesResponse
UA_Client_Service_addReferences(UA_Client *client,
                                const UA_AddReferencesRequest request) {
    UA_AddReferencesResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_ADDREFERENCESREQUEST],
                        &response, &UA_TYPES[UA_TYPES_ADDREFERENCESRESPONSE]);
    return response;
}

static UA_INLINE UA_DeleteNodesResponse
UA_Client_Service_deleteNodes(UA_Client *client,
                              const UA_DeleteNodesRequest request) {
    UA_DeleteNodesResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_DELETENODESREQUEST],
                        &response, &UA_TYPES[UA_TYPES_DELETENODESRESPONSE]);
    return response;
}

static UA_INLINE UA_DeleteReferencesResponse
UA_Client_Service_deleteReferences(UA_Client *client,
                                   const UA_DeleteReferencesRequest request) {
    UA_DeleteReferencesResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_DELETEREFERENCESREQUEST],
                        &response, &UA_TYPES[UA_TYPES_DELETEREFERENCESRESPONSE]);
    return response;
}

/*
 * View Service Set
 * ^^^^^^^^^^^^^^^^ */
static UA_INLINE UA_BrowseResponse
UA_Client_Service_browse(UA_Client *client, const UA_BrowseRequest request) {
    UA_BrowseResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_BROWSEREQUEST],
                        &response, &UA_TYPES[UA_TYPES_BROWSERESPONSE]);
    return response;
}

static UA_INLINE UA_BrowseNextResponse
UA_Client_Service_browseNext(UA_Client *client,
                             const UA_BrowseNextRequest request) {
    UA_BrowseNextResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_BROWSENEXTREQUEST],
                        &response, &UA_TYPES[UA_TYPES_BROWSENEXTRESPONSE]);
    return response;
}

static UA_INLINE UA_TranslateBrowsePathsToNodeIdsResponse
UA_Client_Service_translateBrowsePathsToNodeIds(UA_Client *client,
                        const UA_TranslateBrowsePathsToNodeIdsRequest request) {
    UA_TranslateBrowsePathsToNodeIdsResponse response;
    __UA_Client_Service(client, &request,
                        &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSREQUEST],
                        &response,
                        &UA_TYPES[UA_TYPES_TRANSLATEBROWSEPATHSTONODEIDSRESPONSE]);
    return response;
}

static UA_INLINE UA_RegisterNodesResponse
UA_Client_Service_registerNodes(UA_Client *client,
                                const UA_RegisterNodesRequest request) {
    UA_RegisterNodesResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_REGISTERNODESREQUEST],
                        &response, &UA_TYPES[UA_TYPES_REGISTERNODESRESPONSE]);
    return response;
}

static UA_INLINE UA_UnregisterNodesResponse
UA_Client_Service_unregisterNodes(UA_Client *client,
                                  const UA_UnregisterNodesRequest request) {
    UA_UnregisterNodesResponse response;
    __UA_Client_Service(client, &request,
                        &UA_TYPES[UA_TYPES_UNREGISTERNODESREQUEST],
                        &response, &UA_TYPES[UA_TYPES_UNREGISTERNODESRESPONSE]);
    return response;
}

/*
 * Query Service Set
 * ^^^^^^^^^^^^^^^^^ */
static UA_INLINE UA_QueryFirstResponse
UA_Client_Service_queryFirst(UA_Client *client,
                             const UA_QueryFirstRequest request) {
    UA_QueryFirstResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_QUERYFIRSTREQUEST],
                        &response, &UA_TYPES[UA_TYPES_QUERYFIRSTRESPONSE]);
    return response;
}

static UA_INLINE UA_QueryNextResponse
UA_Client_Service_queryNext(UA_Client *client,
                            const UA_QueryNextRequest request) {
    UA_QueryNextResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_QUERYFIRSTREQUEST],
                        &response, &UA_TYPES[UA_TYPES_QUERYFIRSTRESPONSE]);
    return response;
}

/**
 * .. _client-async-services:
 *
 * Asynchronous Services
 * ---------------------
 * All OPC UA services are asynchronous in nature. So several service calls can
 * be made without waiting for a response first. Responess may come in a
 * different ordering. */

/* Listen on the network and process arriving asynchronous responses in the
 * background. Internal housekeeping and subscription management is done as
 * well. */
UA_StatusCode UA_EXPORT
UA_Client_runAsync(UA_Client *client, UA_UInt16 timeout);

typedef void
(*UA_ClientAsyncServiceCallback)(UA_Client *client, void *userdata,
                                 UA_UInt32 requestId, void *response,
                                 const UA_DataType *responseType);

/* Use the type versions of this method. See below. However, the general
 * mechanism of async service calls is explained here.
 *
 * We say that an async service call has been dispatched once this method
 * returns UA_STATUSCODE_GOOD. If there is an error after an async service has
 * been dispatched, the callback is called with an "empty" response where the
 * statusCode has been set accordingly. This is also done if the client is
 * shutting down and the list of dispatched async services is emptied.
 *
 * The statusCode received when the client is shutting down is
 * UA_STATUSCODE_BADSHUTDOWN.
 *
 * The statusCode received when the client don't receive response
 * after specified config->timeout (in ms) is
 * UA_STATUSCODE_BADTIMEOUT.
 *
 * Instead, you can use __UA_Client_AsyncServiceEx to specify
 * a custom timeout
 *
 * The userdata and requestId arguments can be NULL. */
UA_StatusCode UA_EXPORT
__UA_Client_AsyncService(UA_Client *client, const void *request,
                         const UA_DataType *requestType,
                         UA_ClientAsyncServiceCallback callback,
                         const UA_DataType *responseType,
                         void *userdata, UA_UInt32 *requestId);

/* Use the type versions of this method. See below. However, the general
 * mechanism of async service calls is explained here.
 *
 * We say that an async service call has been dispatched once this method
 * returns UA_STATUSCODE_GOOD. If there is an error after an async service has
 * been dispatched, the callback is called with an "empty" response where the
 * statusCode has been set accordingly. This is also done if the client is
 * shutting down and the list of dispatched async services is emptied.
 *
 * The statusCode received when the client is shutting down is
 * UA_STATUSCODE_BADSHUTDOWN.
 *
 * The statusCode received when the client don't receive response
 * after specified timeout (in ms) is
 * UA_STATUSCODE_BADTIMEOUT.
 *
 * The timeout can be disabled by setting timeout to 0
 *
 * The userdata and requestId arguments can be NULL. */
UA_StatusCode UA_EXPORT
__UA_Client_AsyncServiceEx(UA_Client *client, const void *request,
                           const UA_DataType *requestType,
                           UA_ClientAsyncServiceCallback callback,
                           const UA_DataType *responseType,
                           void *userdata, UA_UInt32 *requestId,
                           UA_UInt32 timeout);

static UA_INLINE UA_StatusCode
UA_Client_AsyncService_read(UA_Client *client, const UA_ReadRequest *request,
                            UA_ClientAsyncServiceCallback callback,
                            void *userdata, UA_UInt32 *requestId) {
    return __UA_Client_AsyncService(client, (const void*)request,
                                    &UA_TYPES[UA_TYPES_READREQUEST], callback,
                                    &UA_TYPES[UA_TYPES_READRESPONSE],
                                    userdata, requestId);
}

static UA_INLINE UA_StatusCode
UA_Client_AsyncService_write(UA_Client *client, const UA_WriteRequest *request,
                             UA_ClientAsyncServiceCallback callback,
                             void *userdata, UA_UInt32 *requestId) {
    return __UA_Client_AsyncService(client, (const void*)request,
                                    &UA_TYPES[UA_TYPES_WRITEREQUEST], callback, 
                                    &UA_TYPES[UA_TYPES_WRITERESPONSE],
                                    userdata, requestId);
}

static UA_INLINE UA_StatusCode
UA_Client_AsyncService_call(UA_Client *client, const UA_CallRequest *request,
                            UA_ClientAsyncServiceCallback callback,
                            void *userdata, UA_UInt32 *requestId) {
    return __UA_Client_AsyncService(client, (const void*)request,
                                    &UA_TYPES[UA_TYPES_CALLREQUEST], callback,
                                    &UA_TYPES[UA_TYPES_CALLRESPONSE],
                                    userdata, requestId);
}

static UA_INLINE UA_StatusCode
UA_Client_AsyncService_browse(UA_Client *client, const UA_BrowseRequest *request,
                              UA_ClientAsyncServiceCallback callback,
                              void *userdata, UA_UInt32 *requestId) {
    return __UA_Client_AsyncService(client, (const void*)request,
                                    &UA_TYPES[UA_TYPES_BROWSEREQUEST], callback,
                                    &UA_TYPES[UA_TYPES_BROWSERESPONSE],
                                    userdata, requestId);
}

/**
 * .. toctree::
 *
 *    client_highlevel
 *    client_subscriptions */

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_client_highlevel.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2015-2018 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2015 (c) Oleksiy Vasylyev
 *    Copyright 2017 (c) Florian Palm
 *    Copyright 2016 (c) Chris Iatrou
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Frank Meerkötter
 */


#ifdef __cplusplus
extern "C" {
#endif


/**
 * .. _client-highlevel:
 *
 * Highlevel Client Functionality
 * ------------------------------
 *
 * The following definitions are convenience functions making use of the
 * standard OPC UA services in the background. This is a less flexible way of
 * handling the stack, because at many places sensible defaults are presumed; at
 * the same time using these functions is the easiest way of implementing an OPC
 * UA application, as you will not have to consider all the details that go into
 * the OPC UA services. If more flexibility is needed, you can always achieve
 * the same functionality using the raw :ref:`OPC UA services
 * <client-services>`.
 *
 * Read Attributes
 * ^^^^^^^^^^^^^^^
 * The following functions can be used to retrieve a single node attribute. Use
 * the regular service to read several attributes at once. */

/* Don't call this function, use the typed versions */
UA_StatusCode UA_EXPORT
__UA_Client_readAttribute(UA_Client *client, const UA_NodeId *nodeId,
                          UA_AttributeId attributeId, void *out,
                          const UA_DataType *outDataType);

static UA_INLINE UA_StatusCode
UA_Client_readNodeIdAttribute(UA_Client *client, const UA_NodeId nodeId,
                              UA_NodeId *outNodeId) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_NODEID,
                                     outNodeId, &UA_TYPES[UA_TYPES_NODEID]);
}

static UA_INLINE UA_StatusCode
UA_Client_readNodeClassAttribute(UA_Client *client, const UA_NodeId nodeId,
                                 UA_NodeClass *outNodeClass) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_NODECLASS,
                                     outNodeClass, &UA_TYPES[UA_TYPES_NODECLASS]);
}

static UA_INLINE UA_StatusCode
UA_Client_readBrowseNameAttribute(UA_Client *client, const UA_NodeId nodeId,
                                  UA_QualifiedName *outBrowseName) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_BROWSENAME,
                                     outBrowseName,
                                     &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
}

static UA_INLINE UA_StatusCode
UA_Client_readDisplayNameAttribute(UA_Client *client, const UA_NodeId nodeId,
                                   UA_LocalizedText *outDisplayName) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_DISPLAYNAME,
                                     outDisplayName,
                                     &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE UA_StatusCode
UA_Client_readDescriptionAttribute(UA_Client *client, const UA_NodeId nodeId,
                                   UA_LocalizedText *outDescription) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_DESCRIPTION,
                                     outDescription,
                                     &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE UA_StatusCode
UA_Client_readWriteMaskAttribute(UA_Client *client, const UA_NodeId nodeId,
                                 UA_UInt32 *outWriteMask) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_WRITEMASK,
                                     outWriteMask, &UA_TYPES[UA_TYPES_UINT32]);
}

static UA_INLINE UA_StatusCode
UA_Client_readUserWriteMaskAttribute(UA_Client *client, const UA_NodeId nodeId,
                                     UA_UInt32 *outUserWriteMask) {
    return __UA_Client_readAttribute(client, &nodeId,
                                     UA_ATTRIBUTEID_USERWRITEMASK,
                                     outUserWriteMask,
                                     &UA_TYPES[UA_TYPES_UINT32]);
}

static UA_INLINE UA_StatusCode
UA_Client_readIsAbstractAttribute(UA_Client *client, const UA_NodeId nodeId,
                                  UA_Boolean *outIsAbstract) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_ISABSTRACT,
                                     outIsAbstract, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_readSymmetricAttribute(UA_Client *client, const UA_NodeId nodeId,
                                 UA_Boolean *outSymmetric) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_SYMMETRIC,
                                     outSymmetric, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_readInverseNameAttribute(UA_Client *client, const UA_NodeId nodeId,
                                   UA_LocalizedText *outInverseName) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_INVERSENAME,
                                     outInverseName,
                                     &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE UA_StatusCode
UA_Client_readContainsNoLoopsAttribute(UA_Client *client, const UA_NodeId nodeId,
                                       UA_Boolean *outContainsNoLoops) {
    return __UA_Client_readAttribute(client, &nodeId,
                                     UA_ATTRIBUTEID_CONTAINSNOLOOPS,
                                     outContainsNoLoops,
                                     &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_readEventNotifierAttribute(UA_Client *client, const UA_NodeId nodeId,
                                     UA_Byte *outEventNotifier) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_EVENTNOTIFIER,
                                     outEventNotifier, &UA_TYPES[UA_TYPES_BYTE]);
}

static UA_INLINE UA_StatusCode
UA_Client_readValueAttribute(UA_Client *client, const UA_NodeId nodeId,
                             UA_Variant *outValue) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_VALUE,
                                     outValue, &UA_TYPES[UA_TYPES_VARIANT]);
}

static UA_INLINE UA_StatusCode
UA_Client_readDataTypeAttribute(UA_Client *client, const UA_NodeId nodeId,
                                UA_NodeId *outDataType) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_DATATYPE,
                                     outDataType, &UA_TYPES[UA_TYPES_NODEID]);
}

static UA_INLINE UA_StatusCode
UA_Client_readValueRankAttribute(UA_Client *client, const UA_NodeId nodeId,
                                 UA_Int32 *outValueRank) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_VALUERANK,
                                     outValueRank, &UA_TYPES[UA_TYPES_INT32]);
}

UA_StatusCode UA_EXPORT
UA_Client_readArrayDimensionsAttribute(UA_Client *client, const UA_NodeId nodeId,
                                       size_t *outArrayDimensionsSize,
                                       UA_UInt32 **outArrayDimensions);

static UA_INLINE UA_StatusCode
UA_Client_readAccessLevelAttribute(UA_Client *client, const UA_NodeId nodeId,
                                   UA_Byte *outAccessLevel) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_ACCESSLEVEL,
                                     outAccessLevel, &UA_TYPES[UA_TYPES_BYTE]);
}

static UA_INLINE UA_StatusCode
UA_Client_readUserAccessLevelAttribute(UA_Client *client, const UA_NodeId nodeId,
                                       UA_Byte *outUserAccessLevel) {
    return __UA_Client_readAttribute(client, &nodeId,
                                     UA_ATTRIBUTEID_USERACCESSLEVEL,
                                     outUserAccessLevel,
                                     &UA_TYPES[UA_TYPES_BYTE]);
}

static UA_INLINE UA_StatusCode
UA_Client_readMinimumSamplingIntervalAttribute(UA_Client *client,
                                               const UA_NodeId nodeId,
                                               UA_Double *outMinSamplingInterval) {
    return __UA_Client_readAttribute(client, &nodeId,
                                     UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL,
                                     outMinSamplingInterval,
                                     &UA_TYPES[UA_TYPES_DOUBLE]);
}

static UA_INLINE UA_StatusCode
UA_Client_readHistorizingAttribute(UA_Client *client, const UA_NodeId nodeId,
                                   UA_Boolean *outHistorizing) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_HISTORIZING,
                                     outHistorizing, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_readExecutableAttribute(UA_Client *client, const UA_NodeId nodeId,
                                  UA_Boolean *outExecutable) {
    return __UA_Client_readAttribute(client, &nodeId, UA_ATTRIBUTEID_EXECUTABLE,
                                     outExecutable, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_readUserExecutableAttribute(UA_Client *client, const UA_NodeId nodeId,
                                      UA_Boolean *outUserExecutable) {
    return __UA_Client_readAttribute(client, &nodeId,
                                     UA_ATTRIBUTEID_USEREXECUTABLE,
                                     outUserExecutable,
                                     &UA_TYPES[UA_TYPES_BOOLEAN]);
}

/**
 * Write Attributes
 * ^^^^^^^^^^^^^^^^
 *
 * The following functions can be use to write a single node attribute at a
 * time. Use the regular write service to write several attributes at once. */
/* Don't call this function, use the typed versions */
UA_StatusCode UA_EXPORT
__UA_Client_writeAttribute(UA_Client *client, const UA_NodeId *nodeId,
                           UA_AttributeId attributeId, const void *in,
                           const UA_DataType *inDataType);

static UA_INLINE UA_StatusCode
UA_Client_writeNodeIdAttribute(UA_Client *client, const UA_NodeId nodeId,
                               const UA_NodeId *newNodeId) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_NODEID,
                                      newNodeId, &UA_TYPES[UA_TYPES_NODEID]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeNodeClassAttribute(UA_Client *client, const UA_NodeId nodeId,
                                  const UA_NodeClass *newNodeClass) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_NODECLASS,
                                      newNodeClass, &UA_TYPES[UA_TYPES_NODECLASS]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeBrowseNameAttribute(UA_Client *client, const UA_NodeId nodeId,
                                   const UA_QualifiedName *newBrowseName) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_BROWSENAME,
                                      newBrowseName,
                                      &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeDisplayNameAttribute(UA_Client *client, const UA_NodeId nodeId,
                                    const UA_LocalizedText *newDisplayName) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_DISPLAYNAME,
                                      newDisplayName,
                                      &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeDescriptionAttribute(UA_Client *client, const UA_NodeId nodeId,
                                    const UA_LocalizedText *newDescription) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_DESCRIPTION,
                                      newDescription,
                                      &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeWriteMaskAttribute(UA_Client *client, const UA_NodeId nodeId,
                                  const UA_UInt32 *newWriteMask) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_WRITEMASK,
                                      newWriteMask, &UA_TYPES[UA_TYPES_UINT32]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeUserWriteMaskAttribute(UA_Client *client, const UA_NodeId nodeId,
                                      const UA_UInt32 *newUserWriteMask) {
    return __UA_Client_writeAttribute(client, &nodeId,
                                      UA_ATTRIBUTEID_USERWRITEMASK,
                                      newUserWriteMask,
                                      &UA_TYPES[UA_TYPES_UINT32]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeIsAbstractAttribute(UA_Client *client, const UA_NodeId nodeId,
                                   const UA_Boolean *newIsAbstract) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_ISABSTRACT,
                                      newIsAbstract, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeSymmetricAttribute(UA_Client *client, const UA_NodeId nodeId,
                                  const UA_Boolean *newSymmetric) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_SYMMETRIC,
                                      newSymmetric, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeInverseNameAttribute(UA_Client *client, const UA_NodeId nodeId,
                                    const UA_LocalizedText *newInverseName) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_INVERSENAME,
                                      newInverseName,
                                      &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeContainsNoLoopsAttribute(UA_Client *client, const UA_NodeId nodeId,
                                        const UA_Boolean *newContainsNoLoops) {
    return __UA_Client_writeAttribute(client, &nodeId,
                                      UA_ATTRIBUTEID_CONTAINSNOLOOPS,
                                      newContainsNoLoops,
                                      &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeEventNotifierAttribute(UA_Client *client, const UA_NodeId nodeId,
                                      const UA_Byte *newEventNotifier) {
    return __UA_Client_writeAttribute(client, &nodeId,
                                      UA_ATTRIBUTEID_EVENTNOTIFIER,
                                      newEventNotifier,
                                      &UA_TYPES[UA_TYPES_BYTE]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeValueAttribute(UA_Client *client, const UA_NodeId nodeId,
                              const UA_Variant *newValue) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_VALUE,
                                      newValue, &UA_TYPES[UA_TYPES_VARIANT]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeDataTypeAttribute(UA_Client *client, const UA_NodeId nodeId,
                                 const UA_NodeId *newDataType) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_DATATYPE,
                                      newDataType, &UA_TYPES[UA_TYPES_NODEID]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeValueRankAttribute(UA_Client *client, const UA_NodeId nodeId,
                                  const UA_Int32 *newValueRank) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_VALUERANK,
                                      newValueRank, &UA_TYPES[UA_TYPES_INT32]);
}

UA_StatusCode UA_EXPORT
UA_Client_writeArrayDimensionsAttribute(UA_Client *client, const UA_NodeId nodeId,
                                        size_t newArrayDimensionsSize,
                                        const UA_UInt32 *newArrayDimensions);

static UA_INLINE UA_StatusCode
UA_Client_writeAccessLevelAttribute(UA_Client *client, const UA_NodeId nodeId,
                                    const UA_Byte *newAccessLevel) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_ACCESSLEVEL,
                                      newAccessLevel, &UA_TYPES[UA_TYPES_BYTE]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeUserAccessLevelAttribute(UA_Client *client, const UA_NodeId nodeId,
                                        const UA_Byte *newUserAccessLevel) {
    return __UA_Client_writeAttribute(client, &nodeId,
                                      UA_ATTRIBUTEID_USERACCESSLEVEL,
                                      newUserAccessLevel,
                                      &UA_TYPES[UA_TYPES_BYTE]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeMinimumSamplingIntervalAttribute(UA_Client *client,
                                                const UA_NodeId nodeId,
                                                const UA_Double *newMinInterval) {
    return __UA_Client_writeAttribute(client, &nodeId,
                                      UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL,
                                      newMinInterval, &UA_TYPES[UA_TYPES_DOUBLE]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeHistorizingAttribute(UA_Client *client, const UA_NodeId nodeId,
                                    const UA_Boolean *newHistorizing) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_HISTORIZING,
                                      newHistorizing, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeExecutableAttribute(UA_Client *client, const UA_NodeId nodeId,
                                   const UA_Boolean *newExecutable) {
    return __UA_Client_writeAttribute(client, &nodeId, UA_ATTRIBUTEID_EXECUTABLE,
                                      newExecutable, &UA_TYPES[UA_TYPES_BOOLEAN]);
}

static UA_INLINE UA_StatusCode
UA_Client_writeUserExecutableAttribute(UA_Client *client, const UA_NodeId nodeId,
                                       const UA_Boolean *newUserExecutable) {
    return __UA_Client_writeAttribute(client, &nodeId,
                                      UA_ATTRIBUTEID_USEREXECUTABLE,
                                      newUserExecutable,
                                      &UA_TYPES[UA_TYPES_BOOLEAN]);
}

/**
 * Method Calling
 * ^^^^^^^^^^^^^^ */
UA_StatusCode UA_EXPORT
UA_Client_call(UA_Client *client, const UA_NodeId objectId,
               const UA_NodeId methodId, size_t inputSize, const UA_Variant *input,
               size_t *outputSize, UA_Variant **output);

/**
 * Node Management
 * ^^^^^^^^^^^^^^^
 * See the section on :ref:`server-side node management <addnodes>`. */
UA_StatusCode UA_EXPORT
UA_Client_addReference(UA_Client *client, const UA_NodeId sourceNodeId,
                       const UA_NodeId referenceTypeId, UA_Boolean isForward,
                       const UA_String targetServerUri,
                       const UA_ExpandedNodeId targetNodeId,
                       UA_NodeClass targetNodeClass);

UA_StatusCode UA_EXPORT
UA_Client_deleteReference(UA_Client *client, const UA_NodeId sourceNodeId,
                          const UA_NodeId referenceTypeId, UA_Boolean isForward,
                          const UA_ExpandedNodeId targetNodeId,
                          UA_Boolean deleteBidirectional);

UA_StatusCode UA_EXPORT
UA_Client_deleteNode(UA_Client *client, const UA_NodeId nodeId,
                     UA_Boolean deleteTargetReferences);

/* Protect against redundant definitions for server/client */
#ifndef UA_DEFAULT_ATTRIBUTES_DEFINED
#define UA_DEFAULT_ATTRIBUTES_DEFINED
/* The default for variables is "BaseDataType" for the datatype, -2 for the
 * valuerank and a read-accesslevel. */
UA_EXPORT extern const UA_VariableAttributes UA_VariableAttributes_default;
UA_EXPORT extern const UA_VariableTypeAttributes UA_VariableTypeAttributes_default;
/* Methods are executable by default */
UA_EXPORT extern const UA_MethodAttributes UA_MethodAttributes_default;
/* The remaining attribute definitions are currently all zeroed out */
UA_EXPORT extern const UA_ObjectAttributes UA_ObjectAttributes_default;
UA_EXPORT extern const UA_ObjectTypeAttributes UA_ObjectTypeAttributes_default;
UA_EXPORT extern const UA_ReferenceTypeAttributes UA_ReferenceTypeAttributes_default;
UA_EXPORT extern const UA_DataTypeAttributes UA_DataTypeAttributes_default;
UA_EXPORT extern const UA_ViewAttributes UA_ViewAttributes_default;
#endif

/* Don't call this function, use the typed versions */
UA_StatusCode UA_EXPORT
__UA_Client_addNode(UA_Client *client, const UA_NodeClass nodeClass,
                    const UA_NodeId requestedNewNodeId,
                    const UA_NodeId parentNodeId,
                    const UA_NodeId referenceTypeId,
                    const UA_QualifiedName browseName,
                    const UA_NodeId typeDefinition, const UA_NodeAttributes *attr,
                    const UA_DataType *attributeType, UA_NodeId *outNewNodeId);

static UA_INLINE UA_StatusCode
UA_Client_addVariableNode(UA_Client *client, const UA_NodeId requestedNewNodeId,
                          const UA_NodeId parentNodeId,
                          const UA_NodeId referenceTypeId,
                          const UA_QualifiedName browseName,
                          const UA_NodeId typeDefinition,
                          const UA_VariableAttributes attr,
                          UA_NodeId *outNewNodeId) {
    return __UA_Client_addNode(client, UA_NODECLASS_VARIABLE, requestedNewNodeId,
                               parentNodeId, referenceTypeId, browseName,
                               typeDefinition, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_VARIABLEATTRIBUTES],
                               outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Client_addVariableTypeNode(UA_Client *client,
                              const UA_NodeId requestedNewNodeId,
                              const UA_NodeId parentNodeId,
                              const UA_NodeId referenceTypeId,
                              const UA_QualifiedName browseName,
                              const UA_VariableTypeAttributes attr,
                              UA_NodeId *outNewNodeId) {
    return __UA_Client_addNode(client, UA_NODECLASS_VARIABLETYPE,
                               requestedNewNodeId,
                               parentNodeId, referenceTypeId, browseName,
                               UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_VARIABLETYPEATTRIBUTES],
                               outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Client_addObjectNode(UA_Client *client, const UA_NodeId requestedNewNodeId,
                        const UA_NodeId parentNodeId,
                        const UA_NodeId referenceTypeId,
                        const UA_QualifiedName browseName,
                        const UA_NodeId typeDefinition,
                        const UA_ObjectAttributes attr, UA_NodeId *outNewNodeId) {
    return __UA_Client_addNode(client, UA_NODECLASS_OBJECT, requestedNewNodeId,
                               parentNodeId, referenceTypeId, browseName,
                               typeDefinition, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_OBJECTATTRIBUTES], outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Client_addObjectTypeNode(UA_Client *client, const UA_NodeId requestedNewNodeId,
                            const UA_NodeId parentNodeId,
                            const UA_NodeId referenceTypeId,
                            const UA_QualifiedName browseName,
                            const UA_ObjectTypeAttributes attr,
                            UA_NodeId *outNewNodeId) {
    return __UA_Client_addNode(client, UA_NODECLASS_OBJECTTYPE, requestedNewNodeId,
                               parentNodeId, referenceTypeId, browseName,
                               UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_OBJECTTYPEATTRIBUTES],
                               outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Client_addViewNode(UA_Client *client, const UA_NodeId requestedNewNodeId,
                      const UA_NodeId parentNodeId,
                      const UA_NodeId referenceTypeId,
                      const UA_QualifiedName browseName,
                      const UA_ViewAttributes attr,
                      UA_NodeId *outNewNodeId) {
    return __UA_Client_addNode(client, UA_NODECLASS_VIEW, requestedNewNodeId,
                               parentNodeId, referenceTypeId, browseName,
                               UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_VIEWATTRIBUTES], outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Client_addReferenceTypeNode(UA_Client *client,
                               const UA_NodeId requestedNewNodeId,
                               const UA_NodeId parentNodeId,
                               const UA_NodeId referenceTypeId,
                               const UA_QualifiedName browseName,
                               const UA_ReferenceTypeAttributes attr,
                               UA_NodeId *outNewNodeId) {
    return __UA_Client_addNode(client, UA_NODECLASS_REFERENCETYPE,
                               requestedNewNodeId,
                               parentNodeId, referenceTypeId, browseName,
                               UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_REFERENCETYPEATTRIBUTES],
                               outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Client_addDataTypeNode(UA_Client *client, const UA_NodeId requestedNewNodeId,
                          const UA_NodeId parentNodeId,
                          const UA_NodeId referenceTypeId,
                          const UA_QualifiedName browseName,
                          const UA_DataTypeAttributes attr,
                          UA_NodeId *outNewNodeId) {
    return __UA_Client_addNode(client, UA_NODECLASS_DATATYPE, requestedNewNodeId,
                               parentNodeId, referenceTypeId, browseName,
                               UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_DATATYPEATTRIBUTES],
                               outNewNodeId);
}

static UA_INLINE UA_StatusCode
UA_Client_addMethodNode(UA_Client *client, const UA_NodeId requestedNewNodeId,
                        const UA_NodeId parentNodeId,
                        const UA_NodeId referenceTypeId,
                        const UA_QualifiedName browseName,
                        const UA_MethodAttributes attr,
                        UA_NodeId *outNewNodeId) {
    return __UA_Client_addNode(client, UA_NODECLASS_METHOD, requestedNewNodeId,
                               parentNodeId, referenceTypeId, browseName,
                               UA_NODEID_NULL, (const UA_NodeAttributes*)&attr,
                               &UA_TYPES[UA_TYPES_METHODATTRIBUTES], outNewNodeId);
}

/**
 * Misc Highlevel Functionality
 * ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
/* Get the namespace-index of a namespace-URI
 *
 * @param client The UA_Client struct for this connection
 * @param namespaceUri The interested namespace URI
 * @param namespaceIndex The namespace index of the URI. The value is unchanged
 *        in case of an error
 * @return Indicates whether the operation succeeded or returns an error code */
UA_StatusCode UA_EXPORT
UA_Client_NamespaceGetIndex(UA_Client *client, UA_String *namespaceUri,
                            UA_UInt16 *namespaceIndex);

#ifndef HAVE_NODEITER_CALLBACK
#define HAVE_NODEITER_CALLBACK
/* Iterate over all nodes referenced by parentNodeId by calling the callback
   function for each child node */
typedef UA_StatusCode (*UA_NodeIteratorCallback)(UA_NodeId childId, UA_Boolean isInverse,
                                                 UA_NodeId referenceTypeId, void *handle);
#endif

UA_StatusCode UA_EXPORT
UA_Client_forEachChildNodeCall(UA_Client *client, UA_NodeId parentNodeId,
                               UA_NodeIteratorCallback callback, void *handle) ;

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/include/ua_client_subscriptions.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


#ifdef __cplusplus
extern "C" {
#endif


#ifdef UA_ENABLE_SUBSCRIPTIONS

/**
 * .. _client-subscriptions:
 *
 * Subscriptions
 * -------------
 *
 * Subscriptions in OPC UA are asynchronous. That is, the client sends several
 * PublishRequests to the server. The server returns PublishResponses with
 * notifications. But only when a notification has been generated. The client
 * does not wait for the responses and continues normal operations.
 *
 * Note the difference between Subscriptions and MonitoredItems. Subscriptions
 * are used to report back notifications. MonitoredItems are used to generate
 * notifications. Every MonitoredItem is attached to exactly one Subscription.
 * And a Subscription can contain many MonitoredItems.
 *
 * The client automatically processes PublishResponses (with a callback) in the
 * background and keeps enough PublishRequests in transit. The PublishResponses
 * may be recieved during a synchronous service call or in
 * ``UA_Client_runAsync``. */

/* Callbacks defined for Subscriptions */
typedef void (*UA_Client_DeleteSubscriptionCallback)
    (UA_Client *client, UA_UInt32 subId, void *subContext);

typedef void (*UA_Client_StatusChangeNotificationCallback)
    (UA_Client *client, UA_UInt32 subId, void *subContext,
     UA_StatusChangeNotification *notification);

/* Provides default values for a new subscription.
 *
 * RequestedPublishingInterval:  500.0 [ms]
 * RequestedLifetimeCount: 10000
 * RequestedMaxKeepAliveCount: 10
 * MaxNotificationsPerPublish: 0 (unlimited)
 * PublishingEnabled: true
 * Priority: 0 */
static UA_INLINE UA_CreateSubscriptionRequest
UA_CreateSubscriptionRequest_default(void) {
    UA_CreateSubscriptionRequest request;
    UA_CreateSubscriptionRequest_init(&request);

    request.requestedPublishingInterval = 500.0;
    request.requestedLifetimeCount = 10000;
    request.requestedMaxKeepAliveCount = 10;
    request.maxNotificationsPerPublish = 0;
    request.publishingEnabled = true;
    request.priority = 0;
    return request;
}

UA_CreateSubscriptionResponse UA_EXPORT
UA_Client_Subscriptions_create(UA_Client *client,
                               const UA_CreateSubscriptionRequest request,
                               void *subscriptionContext,
                               UA_Client_StatusChangeNotificationCallback statusChangeCallback,
                               UA_Client_DeleteSubscriptionCallback deleteCallback);

UA_ModifySubscriptionResponse UA_EXPORT
UA_Client_Subscriptions_modify(UA_Client *client, const UA_ModifySubscriptionRequest request);

UA_DeleteSubscriptionsResponse UA_EXPORT
UA_Client_Subscriptions_delete(UA_Client *client,
                               const UA_DeleteSubscriptionsRequest request);

/* Delete a single subscription */
UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_deleteSingle(UA_Client *client, UA_UInt32 subscriptionId);

static UA_INLINE UA_SetPublishingModeResponse
UA_Client_Subscriptions_setPublishingMode(UA_Client *client,
                                          const UA_SetPublishingModeRequest request) {
    UA_SetPublishingModeResponse response;
    __UA_Client_Service(client, &request,
                        &UA_TYPES[UA_TYPES_SETPUBLISHINGMODEREQUEST], &response,
                        &UA_TYPES[UA_TYPES_SETPUBLISHINGMODERESPONSE]);
    return response;
}

/**
 * MonitoredItems
 * --------------
 *
 * MonitoredItems for Events indicate the ``EventNotifier`` attribute. This
 * indicates to the server not to monitor changes of the attribute, but to
 * forward Event notifications from that node.
 *
 * During the creation of a MonitoredItem, the server may return changed
 * adjusted parameters. Use ``UA_Client_MonitoredItem_getParameters`` to get the
 * current parameters. */

/* Provides default values for a new monitored item. */
static UA_INLINE UA_MonitoredItemCreateRequest
UA_MonitoredItemCreateRequest_default(UA_NodeId nodeId) {
    UA_MonitoredItemCreateRequest request;
    UA_MonitoredItemCreateRequest_init(&request);
    request.itemToMonitor.nodeId = nodeId;
    request.itemToMonitor.attributeId = UA_ATTRIBUTEID_VALUE;
    request.monitoringMode = UA_MONITORINGMODE_REPORTING;
    request.requestedParameters.samplingInterval = 250;
    request.requestedParameters.discardOldest = true;
    request.requestedParameters.queueSize = 1;
    return request;
}

/* Callback for the deletion of a MonitoredItem */
typedef void (*UA_Client_DeleteMonitoredItemCallback)
    (UA_Client *client, UA_UInt32 subId, void *subContext,
     UA_UInt32 monId, void *monContext);

/* Callback for DataChange notifications */
typedef void (*UA_Client_DataChangeNotificationCallback)
    (UA_Client *client, UA_UInt32 subId, void *subContext,
     UA_UInt32 monId, void *monContext,
     UA_DataValue *value);

/* Callback for Event notifications */
typedef void (*UA_Client_EventNotificationCallback)
    (UA_Client *client, UA_UInt32 subId, void *subContext,
     UA_UInt32 monId, void *monContext,
     size_t nEventFields, UA_Variant *eventFields);

/* Don't use to monitor the EventNotifier attribute */
UA_CreateMonitoredItemsResponse UA_EXPORT
UA_Client_MonitoredItems_createDataChanges(UA_Client *client,
            const UA_CreateMonitoredItemsRequest request, void **contexts,
            UA_Client_DataChangeNotificationCallback *callbacks,
            UA_Client_DeleteMonitoredItemCallback *deleteCallbacks);

UA_MonitoredItemCreateResult UA_EXPORT
UA_Client_MonitoredItems_createDataChange(UA_Client *client, UA_UInt32 subscriptionId,
          UA_TimestampsToReturn timestampsToReturn, const UA_MonitoredItemCreateRequest item,
          void *context, UA_Client_DataChangeNotificationCallback callback,
          UA_Client_DeleteMonitoredItemCallback deleteCallback);

/* Monitor the EventNotifier attribute only */
UA_CreateMonitoredItemsResponse UA_EXPORT
UA_Client_MonitoredItems_createEvents(UA_Client *client,
            const UA_CreateMonitoredItemsRequest request, void **contexts,
            UA_Client_EventNotificationCallback *callbacks,
            UA_Client_DeleteMonitoredItemCallback *deleteCallback);

UA_MonitoredItemCreateResult UA_EXPORT
UA_Client_MonitoredItems_createEvent(UA_Client *client, UA_UInt32 subscriptionId,
          UA_TimestampsToReturn timestampsToReturn, const UA_MonitoredItemCreateRequest item,
          void *context, UA_Client_EventNotificationCallback callback,
          UA_Client_DeleteMonitoredItemCallback deleteCallback);

UA_DeleteMonitoredItemsResponse UA_EXPORT
UA_Client_MonitoredItems_delete(UA_Client *client, const UA_DeleteMonitoredItemsRequest);

UA_StatusCode UA_EXPORT
UA_Client_MonitoredItems_deleteSingle(UA_Client *client, UA_UInt32 subscriptionId, UA_UInt32 monitoredItemId);

/**
 * The following service calls go directly to the server. The MonitoredItem settings are
 * not stored in the client. */

static UA_INLINE UA_ModifyMonitoredItemsResponse
UA_Client_MonitoredItems_modify(UA_Client *client,
                                const UA_ModifyMonitoredItemsRequest request) {
    UA_ModifyMonitoredItemsResponse response;
    __UA_Client_Service(client,
                        &request, &UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSREQUEST],
                        &response, &UA_TYPES[UA_TYPES_MODIFYMONITOREDITEMSRESPONSE]);
    return response;
}

static UA_INLINE UA_SetMonitoringModeResponse
UA_Client_MonitoredItems_setMonitoringMode(UA_Client *client,
                                           const UA_SetMonitoringModeRequest request) {
    UA_SetMonitoringModeResponse response;
    __UA_Client_Service(client,
                        &request, &UA_TYPES[UA_TYPES_SETMONITORINGMODEREQUEST],
                        &response, &UA_TYPES[UA_TYPES_SETMONITORINGMODERESPONSE]);
    return response;
}

static UA_INLINE UA_SetTriggeringResponse
UA_Client_MonitoredItems_setTriggering(UA_Client *client,
                                       const UA_SetTriggeringRequest request) {
    UA_SetTriggeringResponse response;
    __UA_Client_Service(client,
                        &request, &UA_TYPES[UA_TYPES_SETTRIGGERINGREQUEST],
                        &response, &UA_TYPES[UA_TYPES_SETTRIGGERINGRESPONSE]);
    return response;
}

/**
 * Deprecated API
 * --------------
 * The following API is kept for backwards compatibility. It will be removed in
 * future releases. */

typedef struct {
    UA_Double requestedPublishingInterval;
    UA_UInt32 requestedLifetimeCount;
    UA_UInt32 requestedMaxKeepAliveCount;
    UA_UInt32 maxNotificationsPerPublish;
    UA_Boolean publishingEnabled;
    UA_Byte priority;
} UA_SubscriptionSettings;

extern const UA_EXPORT UA_SubscriptionSettings UA_SubscriptionSettings_default;

UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_new(UA_Client *client, UA_SubscriptionSettings settings,
                            UA_UInt32 *newSubscriptionId);

UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_remove(UA_Client *client, UA_UInt32 subscriptionId);

/* Send a publish request and wait until a response to the request is processed.
 * Note that other publish responses may be processed in the background until
 * then. */
UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_manuallySendPublishRequest(UA_Client *client);

/* For monitoring DataChanges */
typedef void (*UA_MonitoredItemHandlingFunction)(UA_Client *client, UA_UInt32 monId,
                                                 UA_DataValue *value, void *context);

UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_addMonitoredItems(UA_Client *client, const UA_UInt32 subscriptionId,
                                          UA_MonitoredItemCreateRequest *items, size_t itemsSize,
                                          UA_MonitoredItemHandlingFunction *hfs,
                                          void **hfContexts, UA_StatusCode *itemResults,
                                          UA_UInt32 *newMonitoredItemIds);

UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_addMonitoredItem(UA_Client *client, UA_UInt32 subscriptionId,
                                         UA_NodeId nodeId, UA_UInt32 attributeID,
                                         UA_MonitoredItemHandlingFunction hf,
                                         void *hfContext,
                                         UA_UInt32 *newMonitoredItemId,
                                         UA_Double samplingInterval);

/* Monitored Events have different payloads from DataChanges. So they use a
 * different callback method signature. */
typedef void (*UA_MonitoredEventHandlingFunction)(UA_Client *client,
                                                  const UA_UInt32 monId,
                                                  const size_t nEventFields,
                                                  const UA_Variant *eventFields,
                                                  void *context);

UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_addMonitoredEvents(UA_Client *client, const UA_UInt32 subscriptionId,
                                           UA_MonitoredItemCreateRequest *items, size_t itemsSize,
                                           UA_MonitoredEventHandlingFunction *hfs,
                                           void **hfContexts, UA_StatusCode *itemResults,
                                           UA_UInt32 *newMonitoredItemIds);

/* TODO for 0.4: attribute is fix for events. */
UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_addMonitoredEvent(UA_Client *client, UA_UInt32 subscriptionId,
                                          const UA_NodeId nodeId, UA_UInt32 attributeID,
                                          const UA_SimpleAttributeOperand *selectClauses,
                                          size_t selectClausesSize,
                                          const UA_ContentFilterElement *whereClauses,
                                          size_t whereClausesSize,
                                          const UA_MonitoredEventHandlingFunction hf,
                                          void *hfContext, UA_UInt32 *newMonitoredItemId);

UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_removeMonitoredItem(UA_Client *client, UA_UInt32 subscriptionId,
                                            UA_UInt32 monitoredItemId);

UA_DEPRECATED UA_StatusCode UA_EXPORT
UA_Client_Subscriptions_removeMonitoredItems(UA_Client *client, UA_UInt32 subscriptionId,
                                             UA_UInt32 *monitoredItemIds, size_t itemsSize,
                                             UA_StatusCode *itemResults);

#endif

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_network_tcp.h" ***********************************/

/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2016 (c) Julius Pfrommer, Fraunhofer IOSB
 */


#ifdef __cplusplus
extern "C" {
#endif


UA_ServerNetworkLayer UA_EXPORT
UA_ServerNetworkLayerTCP(UA_ConnectionConfig conf, UA_UInt16 port, UA_Logger logger);

UA_Connection UA_EXPORT
UA_ClientConnectionTCP(UA_ConnectionConfig conf, const char *endpointUrl, const UA_UInt32 timeout, UA_Logger logger);

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_accesscontrol_default.h" ***********************************/

/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2016-2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */



#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    UA_String username;
    UA_String password;
} UA_UsernamePasswordLogin;

/* Default access control. The log-in can be anonymous or username-password. A
 * logged-in user has all access rights. */
UA_EXPORT UA_AccessControl
UA_AccessControl_default(UA_Boolean allowAnonymous,
                         size_t usernamePasswordLoginSize,
                         const UA_UsernamePasswordLogin *usernamePasswordLogin);

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_pki_certificate.h" ***********************************/

/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 */



#ifdef __cplusplus
extern "C" {
#endif

/* Default implementation that accepts all certificates */
UA_EXPORT void
UA_CertificateVerification_AcceptAll(UA_CertificateVerification *cv);

#ifdef UA_ENABLE_ENCRYPTION

/* Accept certificates based on a trust-list and a revocation-list. Based on
 * mbedTLS. */
UA_EXPORT UA_StatusCode
UA_CertificateVerification_Trustlist(UA_CertificateVerification *cv,
                                     const UA_ByteString *certificateTrustList,
                                     size_t certificateTrustListSize,
                                     const UA_ByteString *certificateRevocationList,
                                     size_t certificateRevocationListSize);

#endif

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_securitypolicy_basic128rsa15.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 */

#ifndef UA_SECURITYPOLICY_BASIC128RSA15_H_
#define UA_SECURITYPOLICY_BASIC128RSA15_H_


#ifdef UA_ENABLE_ENCRYPTION

#ifdef __cplusplus
extern "C" {
#endif


UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Basic128Rsa15(UA_SecurityPolicy *policy,
                                UA_CertificateVerification *certificateVerification,
                                const UA_ByteString localCertificate,
                                const UA_ByteString localPrivateKey,
                                UA_Logger logger);

#ifdef __cplusplus
}
#endif

#endif /* UA_ENABLE_ENCRYPTION */

#endif // UA_SECURITYPOLICY_BASIC128RSA15_H_

/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_securitypolicy_basic256sha256.h" ***********************************/

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2018 (c) Daniel Feist, Precitec GmbH & Co. KG
 */

#ifndef UA_SECURITYPOLICY_BASIC256SHA256_H_
#define UA_SECURITYPOLICY_BASIC256SHA256_H_


#ifdef UA_ENABLE_ENCRYPTION

#ifdef __cplusplus
extern "C" {
#endif


UA_EXPORT UA_StatusCode
UA_SecurityPolicy_Basic256Sha256(UA_SecurityPolicy *policy,
                                 UA_CertificateVerification *certificateVerification,
                                 const UA_ByteString localCertificate,
                                 const UA_ByteString localPrivateKey,
                                 UA_Logger logger);

#ifdef __cplusplus
}
#endif

#endif /* UA_ENABLE_ENCRYPTION */

#endif // UA_SECURITYPOLICY_BASIC256SHA256_H_

/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_log_stdout.h" ***********************************/

/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2016 (c) Julius Pfrommer, Fraunhofer IOSB
 */



#ifdef __cplusplus
extern "C" {
#endif

void UA_EXPORT
UA_Log_Stdout(UA_LogLevel level, UA_LogCategory category,
              const char *msg, va_list args);

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_nodestore_default.h" ***********************************/

/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2017 (c) Julian Grothoff
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */



#ifdef __cplusplus
extern "C" {
#endif

/* Initializes the nodestore, sets the context and function pointers */
UA_StatusCode UA_EXPORT
UA_Nodestore_default_new(UA_Nodestore *ns);

#ifdef __cplusplus
} // extern "C"
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_config_default.h" ***********************************/

/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2017 (c) Julius Pfrommer, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 */


#ifdef __cplusplus
extern "C" {
#endif


/**********************/
/* Default Connection */
/**********************/

extern const UA_EXPORT UA_ConnectionConfig UA_ConnectionConfig_default;

/*************************/
/* Default Server Config */
/*************************/

/* Creates a new server config with one endpoint.
 * 
 * The config will set the tcp network layer to the given port and adds a single
 * endpoint with the security policy ``SecurityPolicy#None`` to the server. A
 * server certificate may be supplied but is optional.
 *
 * @param portNumber The port number for the tcp network layer
 * @param certificate Optional certificate for the server endpoint. Can be
 *        ``NULL``. */
UA_EXPORT UA_ServerConfig *
UA_ServerConfig_new_minimal(UA_UInt16 portNumber, const UA_ByteString *certificate);

#ifdef UA_ENABLE_ENCRYPTION

UA_EXPORT UA_ServerConfig *
UA_ServerConfig_new_basic128rsa15(UA_UInt16 portNumber,
                                  const UA_ByteString *certificate,
                                  const UA_ByteString *privateKey,
                                  const UA_ByteString *trustList,
                                  size_t trustListSize,
                                  const UA_ByteString *revocationList,
                                  size_t revocationListSize);

UA_EXPORT UA_ServerConfig *
UA_ServerConfig_new_basic256sha256(UA_UInt16 portNumber,
                                   const UA_ByteString *certificate,
                                   const UA_ByteString *privateKey,
                                   const UA_ByteString *trustList,
                                   size_t trustListSize,
                                   const UA_ByteString *revocationList,
                                   size_t revocationListSize);

UA_EXPORT UA_ServerConfig *
UA_ServerConfig_new_allSecurityPolicies(UA_UInt16 portNumber,
                                        const UA_ByteString *certificate,
                                        const UA_ByteString *privateKey,
                                        const UA_ByteString *trustList,
                                        size_t trustListSize,
                                        const UA_ByteString *revocationList,
                                        size_t revocationListSize);

#endif

/* Creates a server config on the default port 4840 with no server
 * certificate. */
static UA_INLINE UA_ServerConfig *
UA_ServerConfig_new_default(void) {
    return UA_ServerConfig_new_minimal(4840, NULL);
}

/* Set a custom hostname in server configuration
 *
 * @param config A valid server configuration
 * @param customHostname The custom hostname used by the server */

UA_EXPORT void
UA_ServerConfig_set_customHostname(UA_ServerConfig *config,
                                   const UA_String customHostname);

/* Frees allocated memory in the server config */
UA_EXPORT void
UA_ServerConfig_delete(UA_ServerConfig *config);

/*************************/
/* Default Client Config */
/*************************/

extern const UA_EXPORT UA_ClientConfig UA_ClientConfig_default;

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_securitypolicy_none.h" ***********************************/

/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2017 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */


#ifdef __cplusplus
extern "C" {
#endif


UA_StatusCode UA_EXPORT
UA_SecurityPolicy_None(UA_SecurityPolicy *policy, UA_CertificateVerification *certificateVerification,
                       const UA_ByteString localCertificate, UA_Logger logger);

#ifdef __cplusplus
}
#endif


/*********************************** amalgamated original file "/home/travis/build/open62541/open62541/plugins/ua_log_socket_error.h" ***********************************/

/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. 
 *
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */


#ifdef __cplusplus
extern "C" {
#endif


#ifdef _WIN32
#include <winsock2.h>
#define UA_LOG_SOCKET_ERRNO_WRAP(LOG) { \
    char *errno_str = NULL; \
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, \
    NULL, WSAGetLastError(), \
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), \
    (LPSTR)&errno_str, 0, NULL); \
    LOG; \
    LocalFree(errno_str); \
}
#else
#define UA_LOG_SOCKET_ERRNO_WRAP(LOG) { \
    char *errno_str = strerror(errno); \
    LOG; \
}
#endif

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OPEN62541_H_ */
