#ifndef MY_PIN_TOOL_H
#define MY_PIN_TOOL_H

#include "pin.H"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>
#include <string.h>
#include "xed-iclass-enum.h"




typedef enum {type_BYTE,type_WORD,type_DWORD,type_unknown} type_def;

struct TDS{
       UINT32 opcode;  // opcode of operation
       TDS * source;   // pointer to predecessor
       ADDRINT memaddr; // Tainted Address
       ADDRINT offset;// The origin of the taint
	   UINT32 var_length;
	   bool pointer;
	   type_def var_type;
};

struct TYPE_reg{
	bool pointer;
	ADDRINT pointaddr;
	type_def var_type;
};

extern std::ofstream out;// output file
extern std::ifstream in;

extern bool TAINT_Instrumentation_On;
extern map<ADDRINT, TDS * > TaintedAddrs;

VOID AddTaint(ADDRINT toTaintAdd,UINT32 toTaintLen,type_def toTaintType);

#endif