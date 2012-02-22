#ifndef SUMMARY_H
#define SUMMARY_H



#include "MyPinTool.h"

typedef void (*patchfunc)(void* sp);
typedef void (*postpatchfunc)(ADDRINT returnval);

typedef struct funcsum {
  string  lib_name; //name of the library
  string  func_name; // name of the function
  ADDRINT start; // starting address of the function, only used if the function is not described in the symbol database from MS
  patchfunc summary;  // summary function runs before entering the function
  postpatchfunc post_summary; //post_summary runs after exiting the function, with the result of the function as parameters
} funcsum;

extern funcsum summary_table[];

void inst_func_summary(IMG img);

#endif