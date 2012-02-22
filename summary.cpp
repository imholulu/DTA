#include "summary.h"


void patch_WideCharToMultiByte(void* sp)
{
	ADDRINT* esp = (ADDRINT*) sp;
	if(TaintedAddrs.count(esp[3])&&esp[6]!=0)
	{
		out<<endl;
		out<<"function summary:"<<endl<<"WideCharToMultiByte()"<<endl;
		out<<"function argu: "<<endl;
		out<<"lpWideCharStr "<< esp[3] << endl;
		out<<"cchWideChar "<< esp[4] << endl;
		out<<"lpMultiByteStr "<< esp[5] <<endl;
		out<<"cbMultiByte "<< esp[6] <<endl;

			TDS *tds_temp = new TDS;

			tds_temp->source = TaintedAddrs[esp[3]];
			tds_temp->memaddr = esp[5];
			tds_temp->var_length = esp[6];
			tds_temp->var_type = type_BYTE;
			tds_temp->offset = 0;

			TaintedAddrs[esp[5]] = tds_temp;
			
			out <<endl;
			out <<"this variable tainted from address:"<<esp[3]<<endl;
			out <<"tainted variable address: "<<tds_temp->memaddr<<endl;
			out <<"variable type: "<<" character string "<<endl;
			out <<"variable length-byte:"<<tds_temp->var_length<<endl;

			AddTaint(tds_temp->memaddr,tds_temp->var_length,tds_temp->var_type);
	}
}

void patch_wcscpy(void* sp)
{
	ADDRINT* esp = (ADDRINT*) sp;

	if(TaintedAddrs.count(esp[2]))
	{
		out<<endl;
		out<<"function summary:"<<endl<<"wcscpy()"<<endl;
		out<<"function argu: "<<endl;
		out<<"strDestination "<< esp[1] << endl;
		out<<"strSource"<< esp[2] << endl;

		ADDRINT dst = esp[1] ;
        ADDRINT src = esp[2];
        ADDRINT srclen = wcslen((const wchar_t* )src);

		TDS *tds_temp = new TDS;

		tds_temp->source = TaintedAddrs[esp[2]];
		tds_temp->memaddr = esp[1];
		tds_temp->var_length = srclen;
		tds_temp->var_type = type_WORD;
		tds_temp->offset = 0;

		TaintedAddrs[esp[5]] = tds_temp;

		out <<endl;
		out <<"this variable tainted from address:"<<esp[3]<<endl;
		out <<"tainted variable address: "<<tds_temp->memaddr<<endl;
		out <<"variable type: "<<" character string "<<endl;
		out <<"variable length-byte:"<<tds_temp->var_length<<endl;

		AddTaint(tds_temp->memaddr,tds_temp->var_length,tds_temp->var_type);
	}
}


funcsum summary_table[] =
{
	{"kernel32","WideCharToMultiByte",0,patch_WideCharToMultiByte,NULL},
	{"msvcrt","wcscpy",0,patch_wcscpy,NULL}
};

void funcbegin(ADDRINT summary, ADDRINT sp)
{
	TAINT_Instrumentation_On = 0;
	funcsum* fsum = (funcsum*) summary;
	if (fsum->summary)
		fsum->summary((void*) sp);
}

void funcend(ADDRINT summary, ADDRINT returnval)
{
	
	funcsum* fsum = (funcsum*) summary;
	if(fsum->post_summary)
		fsum->post_summary(returnval);
	TAINT_Instrumentation_On = 1;
}

void inst_func_summary(IMG img)
{
	for (int i=0; i< sizeof(summary_table)/sizeof(summary_table[0]);i++)
	{
		if(IMG_Name(img).find(summary_table[i].lib_name)!=string::npos)
		{
			RTN summary_func;
			out<<"find summary dll"<<endl;
			summary_func = RTN_FindByName(img, summary_table[i].func_name.c_str());//summary_table[i].func_name);
			if (RTN_Valid(summary_func))
			{
				RTN_Open(summary_func);
				out << "function summary: "<<endl;
				out << " Image: " << IMG_Name(img).c_str() << " Func: " << summary_table[i].func_name << endl;
				RTN_InsertCall(summary_func, IPOINT_BEFORE, (AFUNPTR)funcbegin,
								IARG_ADDRINT,& (summary_table[i]),IARG_REG_VALUE, REG_STACK_PTR ,IARG_RETURN_REGS, REG_INST_G0,IARG_END);
				RTN_InsertCall(summary_func, IPOINT_AFTER, (AFUNPTR)funcend,
								IARG_ADDRINT,& (summary_table[i]),IARG_FUNCRET_EXITPOINT_VALUE ,IARG_RETURN_REGS, REG_INST_G0,IARG_END);
				RTN_Close(summary_func);
			}
		}
	}
}
