/*
	IDA Loader module for Nintendo DS (NDS) ROM files.
	Written by Dennis Elser.
	Fixed / Updated by Franck Charlet (hitchhikr@australia.edu).
	Reupdated to 6.1 by Rodrigo Iglesias (@Areidz).
    Updated even further to 7.0 by Prince Frizzy (theclashingfritz@gmail.com).

	Comments:
	---------
	This is the first loader module for IDA
	I have written so far. It might therefore
	give inaccurate results.
	Feedback, bugreports and donations are welcome =)

	dennis[at]backtrace[dot]de / www[dot]backtrace[dot]de


	Credits:
	--------
	-	Rafael Vuijk for the CRC16 Code and the
		NDS ROM Header layout
	-	DataRescue for providing loader sourcecode
		with the IDA SDK

	History:
	--------

	2004/12/29 initial version
	
	- can disassemble arm7 or arm9 code
	- can add additional information about
	  the ROM to database

	2005/01/01 version 1.1

	- creates a section for the whole RAM area
	  and maps the cartridge's code into it
	- adds more additional information about
	  the ROM to database

	2006/01/17 version 1.11

	- updated sourcecode to be compatible with IDA4.8 SDK

	2007/10/29 version 1.12

	- updated sourcecode to be compatible with IDA5.x SDK
	- added more infos in header structure
	- fixed the allowed memory ranges
	- added more infos in disassembled header

	2008/07/17 version 1.13

    - correctly positioned at program's entry point
    - corrected the selection of processors

    2015/11/11 version 1.14
    - updated sourcecode to be compatible with IDA6.1 SDK
   
    2017/03/1 version 1.20
    - updated sourcecode to be compatible with IDA7.0 SDK

*/

//#include <ida.hpp>
#include <idaldr.h>
#include "nds.h"

//defines
#define version "v1.20"

//global data
nds_hdr hdr;

//--------------------------------------------------------------------------
//
//		the code of CalcCRC16() has been taken from Rafael Vuijk's "ndstool"
//		and slightly been modified by me
//
unsigned short CalcCRC16(nds_hdr *ndshdr) {
	unsigned short crc16 = 0xFFFF;
	for(int i = 0; i < 350; i++) {
		unsigned char data = *((unsigned char *) ndshdr + i);
		crc16 = (crc16 >> 8) ^ crc16tab[(crc16 ^ data) & 0xFF];
	}
	return crc16;
}

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename) {
	unsigned long filelen;

	// get filesize
	filelen = qlsize(li);

	// quit, if file is smaller than size of NDS header
	if (filelen < sizeof(nds_hdr))
		return 0;

	// set filepos to offset 0
	qlseek(li, 0, SEEK_SET);

	// read whole NDS header
	if (qlread(li, &hdr, sizeof(nds_hdr)) != sizeof(nds_hdr)) {
		return 0;
	}

	// check validity of CRC16 value of header
	// this is used to determine if this file is an NDS file
	if (CalcCRC16(&hdr) != hdr.headerCRC16) {
		return 0;
	}

	// this is the name of the file format which will be
	// displayed in IDA's dialog
	*fileformatname = "Nintendo DS ROM";
	*processor = "arm";

    // Default processor
    

	return (1 | ACCEPT_FIRST);
}


//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *li, ushort neflags, const char *fileformatname) {
    int i;
	ea_t startEA;
	ea_t endEA;
	long offset;
	int ARM9;
    int found_mem_block;
    ea_t entry_point;

    // go to file-offset 0
	qlseek(li, 0, SEEK_SET);

	// and read the whole header
	qlread(li, &hdr, sizeof(nds_hdr));

	// display a messagebox asking the user for details
	//  1 - Yes
	//  0 - No
	// -1 - Cancel
	int answer = vask_yn(1,
		"NDS Loader by Dennis Elser.\n\n"
		"This file possibly contains ARM7 *and* ARM9 code.\n"
		"Choose \"Yes\" to load the ARM9 executable,\n"
		"\"No\" to load the ARM7 executable\n\n"
		"Please note that this loader has not been thoroughly tested!\n"
		"If you discover a bug, please let me know: dennis@backtrace.de\n"
		"\nDo you want to load the ARM9 code?\n\n"
		,NULL
	);

	// user chose "cancel" ?
    if(answer==BADADDR) {
		qexit(1);
    }

	// user chose "yes" = arm9
	if(answer) {
		set_processor_type("ARM", setproc_level_t::SETPROC_LOADER_NON_FATAL);
		// init
		inf.start_ip = inf.start_ea = hdr.arm9_entry_address;
		startEA = hdr.arm9_ram_address;
		endEA = hdr.arm9_ram_address + hdr.arm9_size;
		offset = hdr.arm9_rom_offset;
		ARM9 = true;
		// sanitycheck
		if (qlsize(li) < offset+hdr.arm9_size) {
			loader_failure();
        }
	} else { // user chose "no" = arm7
		set_processor_type("ARM710A", setproc_level_t::SETPROC_LOADER_NON_FATAL);
		// init
		inf.start_ip = inf.start_ea = hdr.arm7_entry_address;
		startEA = hdr.arm7_ram_address;
		endEA = hdr.arm7_ram_address + hdr.arm7_size;
		offset = hdr.arm7_rom_offset;
		ARM9 = false;
		// sanitycheck
		if(qlsize(li) < offset+hdr.arm7_size) {
			loader_failure();
        }
	}
	
	// check if segment lies within legal RAM blocks
    found_mem_block = false;
    for(i = 0; i < sizeof(memory) / sizeof(MEMARRAY); i++) {
      if(startEA >= memory[i].start || endEA <= memory[i].end)  {
            found_mem_block = true;
            break;
       }
    }
    if(!found_mem_block) {
		loader_failure();
    }

	// map selector
	set_selector(1, 0);
	inf.start_cs = 1;

	// create a segment for the legal RAM blocks
	for(i = 0; i < sizeof(memory) / sizeof(MEMARRAY); i++) {
        if (!add_segm(1, memory[i].start, memory[i].end, "RAM", CLASS_CODE)) {
			loader_failure();
        }
    }

	// enable 32bit addressing
	set_segm_addressing(getseg(startEA), 1);

	// load file into RAM area
	file2base(li, offset, startEA, endEA, FILEREG_PATCHABLE);
	
    entry_point = ARM9 == true ? hdr.arm9_entry_address : hdr.arm7_entry_address;

	// add additional information about the ROM to the database
    add_extra_line(startEA, true, ";   Created with NDS Loader %s.\n", version);
	add_extra_line(startEA, true, ";   Author 1:           dennis@backtrace.de");
	add_extra_line(startEA, true, ";   Author 2:           hitchhikr@australia.edu\n");
	add_extra_line(startEA, true, ";   Game Title:         %s\n", hdr.title);
	add_extra_line(startEA, true, ";   Processor:          ARM%c", ARM9 == true ? '9' : '7');
	add_extra_line(startEA, true, ";   ROM Header size:    0x%08X", hdr.headerSize);
	add_extra_line(startEA, true, ";   Header CRC:         0x%04X\n", hdr.headerCRC16);
	add_extra_line(startEA, true, ";   Offset in ROM:      0x%08X", ARM9 == true ? hdr.arm9_rom_offset : hdr.arm7_rom_offset);
	add_extra_line(startEA, true, ";   Array:              0x%08X - 0x%08X (%d bytes)", startEA, endEA, ARM9 == true ? hdr.arm9_size : hdr.arm7_size);
	add_extra_line(startEA, true, ";   Entry point:        0x%08X\n", entry_point);

	add_extra_line(startEA, true, ";   --- Beginning of ROM content ---", NULL);
	if(entry_point != startEA) {
		add_extra_line(entry_point, true, ";   --- Entry point ---", NULL);
	}
	add_extra_line(endEA, true, ";   --- End of ROM content ---", NULL);
    if(entry_point != BADADDR) {
        inf.start_cs = 0;
        inf.start_ip = entry_point;
    }
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC = {
    IDP_INTERFACE_VERSION,
    0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
    accept_file,
//
//      load file into the database.
//
    load_file,
//
//      create output file from the database.
//      this function may be absent.
//
    NULL,
    NULL,
    NULL,
};
