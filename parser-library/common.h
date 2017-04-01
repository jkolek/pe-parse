#ifndef _COMMON_H
#define _COMMON_H

#ifdef _MSC_VER
#define __typeof__(x) std::remove_reference < decltype(x) > ::type
#endif

#define PE_ERR(x)           \
  err = (pe_err) x;         \
  err_loc.assign(__func__); \
  err_loc += ":" + to_string<std::uint32_t>(__LINE__, dec);

#define READ_WORD(b, o, inst, member)                                     \
  if (!readWord(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                   \
    return false;                                                         \
  }

#define READ_DWORD(b, o, inst, member)                                     \
  if (!readDword(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                    \
    return false;                                                          \
  }

#define READ_QWORD(b, o, inst, member)                                     \
  if (!readQword(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                    \
    return false;                                                          \
  }

#define READ_DWORD_PTR(b, o, inst, member)                                   \
  if (!readDword(b, o + _offset(__typeof__(*inst), member), inst->member)) { \
    PE_ERR(PEERR_READ);                                                      \
    return false;                                                            \
  }

#define READ_BYTE(b, o, inst, member)                                     \
  if (!readByte(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                   \
    return false;                                                         \
  }

/* This variant returns NULL instead of false. */
#define READ_DWORD_NULL(b, o, inst, member)                                \
  if (!readDword(b, o + _offset(__typeof__(inst), member), inst.member)) { \
    PE_ERR(PEERR_READ);                                                    \
    return NULL;                                                           \
  }

namespace peparse {

enum pe_err {
  PEERR_NONE = 0,
  PEERR_MEM = 1,
  PEERR_HDR = 2,
  PEERR_SECT = 3,
  PEERR_RESC = 4,
  PEERR_SECTVA = 5,
  PEERR_READ = 6,
  PEERR_OPEN = 7,
  PEERR_STAT = 8,
  PEERR_MAGIC = 9
};

} // namespace peparse

#endif
