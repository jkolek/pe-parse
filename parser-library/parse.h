/* DO WHATEVER YOU WANT */

#ifndef _PARSE_H
#define _PARSE_H
#include <string>
#include <boost/cstdint.hpp>

typedef boost::uint32_t RVA;

typedef struct _bounded_buffer {
  boost::uint8_t  *buf;
  boost::uint32_t bufLen;
  bool            copy;
} bounded_buffer;

bool readByte(bounded_buffer *b, boost::uint32_t offset, boost::uint8_t &out);
bool readWord(bounded_buffer *b, boost::uint32_t offset, boost::uint16_t &out);
bool readDword(bounded_buffer *b, boost::uint32_t offset, boost::uint32_t &out);

bounded_buffer *readFileToFileBuffer(const char *filePath);
bounded_buffer *splitBuffer(bounded_buffer *b, boost::uint32_t from, boost::uint32_t to);
void deleteBuffer(bounded_buffer *b);

struct parsed_pe_internal;

typedef struct _pe_header {
  RVA             entryPoint;
  bounded_buffer  headerData;
} pe_header;

typedef struct _parsed_pe {
  bounded_buffer      *fileBuffer;
  parsed_pe_internal  *internal;
  pe_header           peHeader;
} parsed_pe;

//get a PE parse context from a file 
parsed_pe *ParsePEFromFile(const char *filePath);

//destruct a PE context
void DestructParsedPE(parsed_pe *pe);

//iterate over the imports by RVA and string 
typedef void (*iterRVAStr)(void *, RVA, std::string &);
void IterImpRVAString(parsed_pe *pe, iterRVAStr cb, void *cbd);

//iterate over relocations in the PE file
typedef void (*iterReloc)(void *, RVA);
void IterRelocs(parsed_pe *pe, iterReloc cb, void *cbd);

//iterate over the exports by RVA
typedef void (*iterRVA)(void *, RVA);
void IterExpRVA(parsed_pe *pe, iterRVA cb, void *cbd);

//iterate over sections
typedef void (*iterSec)(void *, RVA secBase, std::string &, bounded_buffer *b);
void IterSec(parsed_pe *pe, iterSec cb, void *cbd);

#endif
