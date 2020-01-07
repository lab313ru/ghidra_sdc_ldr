/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package segadreamcast;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SegaDreamcastLoader extends AbstractLibrarySupportLoader {

	private static final long DEF_RAM_BASE = 0x8C000000L;
	private static final String OPTION_NAME = "RAM Base Address: ";
	private static long ramBase = DEF_RAM_BASE;
	
	@Override
	public String getName() {
		return "Sega Dreamcast Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		
		long size = reader.length();
		if (size == 16 * 1024 * 1024 || size == 32 * 1024 * 1024) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH4:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		createSegments(fpa, log);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,	DomainObject domainObject, boolean isLoadIntoProgram) {
		
		List<Option> list = new ArrayList<>();
		
		list.add(new SegaDreamcastBaseChooser(OPTION_NAME, ramBase, SegaDreamcastBaseChooser.class, Loader.COMMAND_LINE_ARG_PREFIX + "-ramStart"));
		
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(OPTION_NAME)) {
				ramBase = Long.decode((String)option.getValue());
				break;
			}
		}

		return null;
	}
	
	private static void createSegments(FlatProgramAPI fpa, MessageLog log) {
		createCcrSegment(fpa, log);
		createUbcSegment(fpa, log);
		createBscSegment(fpa, log);
		createDmacSegment(fpa, log);
		createCpgSegment(fpa, log);
		createRtcSegment(fpa, log);
		createIntcSegment(fpa, log);
		createTmuSegment(fpa, log);
		createSciSegment(fpa, log);
		createScifSegment(fpa, log);
		createHudiSegment(fpa, log);
	}
	
	private static void createCcrSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "CCN", 0xFF000000L, 0x48, true, false, log);
		createNamedDword(fpa, 0xFF000000L, "CCN_PTEH", "Page table entry high register", log);
		createNamedDword(fpa, 0xFF000004L, "CCN_PTEL", "Page table entry low register", log);
		createNamedDword(fpa, 0xFF000008L, "CCN_TTB", "Translation table base register", log);
		createNamedDword(fpa, 0xFF00000CL, "CCN_TEA", "TLB exception address register", log);
		createNamedDword(fpa, 0xFF000010L, "CCN_MMUCR", "MMU control register", log);
		createNamedByte(fpa,  0xFF000014L, "CCN_BASRA", "Break ASID register A", log);
		createNamedByte(fpa,  0xFF000018L, "CCN_BASRB", "Break ASID register B", log);
		createNamedDword(fpa, 0xFF00001CL, "CCN_CCR", "Cache control register", log);
		createNamedDword(fpa, 0xFF000020L, "CCN_TRA", "TRAPA exception register", log);
		createNamedDword(fpa, 0xFF000024L, "CCN_EXPEVT", "Exception event register", log);
		createNamedDword(fpa, 0xFF000028L, "CCN_INTEVT", "Interrupt event register", log);
		createNamedDword(fpa, 0xFF000030L, "CCN_PVR", "Processor version register", log);
		createNamedDword(fpa, 0xFF000034L, "CCN_PTEA", "Page table entry assistance register", log);
		createNamedDword(fpa, 0xFF000038L, "CCN_QACR0", "Queue address control register 0", log);
		createNamedDword(fpa, 0xFF00003CL, "CCN_QACR1", "Queue address control register 1", log);
		createNamedDword(fpa, 0xFF000044L, "CCN_PRR", "Product register", log);
	}
	
	private static void createUbcSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "UBC", 0xFF200000L, 0x24, true, false, log);
		createNamedDword(fpa, 0xFF200000L, "UBC_BARA", "Break address register A", log);
		createNamedByte(fpa, 0xFF200004L, "UBC_BAMRA", "Break address mask register A", log);
		createNamedWord(fpa, 0xFF200008L, "UBC_BBRA", "Break bus cycle register A", log);
		createNamedDword(fpa, 0xFF20000CL, "UBC_BARB", "Break address register B", log);
		createNamedByte(fpa, 0xFF200010L, "UBC_BAMRB", "Break address mask register B", log);
		createNamedWord(fpa, 0xFF200014L, "UBC_BBRB", "Break bus cycle register B", log);
		createNamedDword(fpa, 0xFF200018L, "UBC_BDRB", "Break data register B", log);
		createNamedDword(fpa, 0xFF20001CL, "UBC_BDMRB", "Break data mask register B", log);
		createNamedWord(fpa, 0xFF200020L, "UBC_BRCR", "Break control register", log);
	}
	
	private static void createBscSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "BSC", 0xFF800000L, 0x4C, true, false, log);
		createNamedDword(fpa, 0xFF800000L, "BSC_BCR1", "Bus control register 1", log);
		createNamedWord(fpa,  0xFF800004L, "BSC_BCR2", "Bus control register 2", log);
		createNamedDword(fpa, 0xFF800008L, "BSC_WCR1", "Wait state control register 1", log);
		createNamedDword(fpa, 0xFF80000CL, "BSC_WCR2", "Wait state control register 2", log);
		createNamedDword(fpa, 0xFF800010L, "BSC_WCR3", "Wait state control register 3", log);
		createNamedDword(fpa, 0xFF800014L, "BSC_MCR", "Memory control register", log);
		createNamedWord(fpa,  0xFF800018L, "BSC_PCR", "PCMCIA control register", log);
		createNamedWord(fpa,  0xFF80001CL, "BSC_RTCSR", "Refresh timer control/status register", log);
		createNamedWord(fpa,  0xFF800020L, "BSC_RTCNT", "Refresh timer counter", log);
		createNamedWord(fpa,  0xFF800024L, "BSC_RTCOR", "Refresh time constant counter", log);
		createNamedWord(fpa,  0xFF800028L, "BSC_RFCR", "Refresh count register", log);
		createNamedDword(fpa, 0xFF80002CL, "BSC_PCTRA", "Port control register A", log);
		createNamedWord(fpa,  0xFF800030L, "BSC_PDTRA", "Port data register A", log);
		createNamedDword(fpa, 0xFF800040L, "BSC_PCTRB", "Port control register B", log);
		createNamedWord(fpa,  0xFF800044L, "BSC_PDTRB", "Port data register B", log);
		createNamedWord(fpa,  0xFF800048L, "BSC_GPIOC", "GPIO interrupt control register", log);
		
		createSegment(fpa, null, "BSC_SDMR2", 0xFF900000L, 0x4, true, false, log);
		createNamedDword(fpa, 0xFF900000L, "BSC_SDMR2", "Synchronous DRAM mode registers for area 2", log);
		
		createSegment(fpa, null, "BSC_SDMR2", 0xFF940000L, 0x4, true, false, log);
		createNamedDword(fpa, 0xFF940000L, "BSC_SDMR3", "Synchronous DRAM mode registers for area 3", log);
	}
	
	private static void createDmacSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "DMAC", 0xFFA00000L, 0x44, true, false, log);
		createNamedDword(fpa, 0xFFA00000L, "DMAC_SAR0", "DMA source address register 0", log);
		createNamedDword(fpa, 0xFFA00004L, "DMAC_DAR0", "DMA destination address register 0", log);
		createNamedDword(fpa, 0xFFA00008L, "DMAC_DMATCR0", "DMA transfer count register 0", log);
		createNamedDword(fpa, 0xFFA0000CL, "DMAC_CHCR0", "DMA channel control register 0", log);
		createNamedDword(fpa, 0xFFA00010L, "DMAC_SAR1", "DMA source address register 1", log);
		createNamedDword(fpa, 0xFFA00014L, "DMAC_DAR1", "DMA destination address register 1", log);
		createNamedDword(fpa, 0xFFA00018L, "DMAC_DMATCR1", "DMA transfer count register 1", log);
		createNamedDword(fpa, 0xFFA0001CL, "DMAC_CHCR1", "DMA channel control register 1", log);
		createNamedDword(fpa, 0xFFA00020L, "DMAC_SAR2", "DMA source address register 2", log);
		createNamedDword(fpa, 0xFFA00024L, "DMAC_DAR2", "DMA destination address register 2", log);
		createNamedDword(fpa, 0xFFA00028L, "DMAC_DMATCR2", "DMA transfer count register 2", log);
		createNamedDword(fpa, 0xFFA0002CL, "DMAC_CHCR2", "DMA channel control register 2", log);
		createNamedDword(fpa, 0xFFA00030L, "DMAC_SAR3", "DMA source address register 3", log);
		createNamedDword(fpa, 0xFFA00034L, "DMAC_DAR3", "DMA destination address register 3", log);
		createNamedDword(fpa, 0xFFA00038L, "DMAC_DMATCR3", "DMA transfer count register 3", log);
		createNamedDword(fpa, 0xFFA0003CL, "DMAC_CHCR3", "DMA channel control register 3", log);
		createNamedDword(fpa, 0xFFA00040L, "DMAC_DMAOR", "DMA operation register", log);
	}
	
	private static void createCpgSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "CPG", 0xFFC00000L, 0x14, true, false, log);
		createNamedWord(fpa, 0xFFC00000L, "CPG_FRQCR", "Frequency control register", log);
		createNamedByte(fpa, 0xFFC00004L, "CPG_STBCR", "Standby control register", log);
		createNamedWord(fpa, 0xFFC00008L, "CPG_WTCNT", "Watchdog timer counter", log);
		createNamedWord(fpa, 0xFFC0000CL, "CPG_WTCSR", "Watchdog timer control/status register", log);
		createNamedByte(fpa, 0xFFC00010L, "CPG_STBCR2", "Standby control register 2", log);
	}
	
	private static void createRtcSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "RTC", 0xFFC80000L, 0x40, true, false, log);
		createNamedByte(fpa, 0xFFC80000L, "RTC_R64CNT", "64 Hz counter", log);
		createNamedByte(fpa, 0xFFC80004L, "RTC_RSECCNT", "Second counter", log);
		createNamedByte(fpa, 0xFFC80008L, "RTC_RMINCNT", "Minute counter", log);
		createNamedByte(fpa, 0xFFC8000CL, "RTC_RHRCNT", "Hour counter", log);
		createNamedByte(fpa, 0xFFC80010L, "RTC_RWKCNT", "Day-of-week counter", log);
		createNamedByte(fpa, 0xFFC80014L, "RTC_RDAYCNT", "Day counter", log);
		createNamedByte(fpa, 0xFFC80018L, "RTC_RMONCNT", "Month counter", log);
		createNamedWord(fpa, 0xFFC8001CL, "RTC_RYRCNT", "Year counter", log);
		createNamedByte(fpa, 0xFFC80020L, "RTC_RSECAR", "Second alarm register", log);
		createNamedByte(fpa, 0xFFC80024L, "RTC_RMINAR", "Minute alarm register", log);
		createNamedByte(fpa, 0xFFC80028L, "RTC_RHRAR", "Hour alarm register", log);
		createNamedByte(fpa, 0xFFC8002CL, "RTC_RWKAR", "Day-of-week alarm register", log);
		createNamedByte(fpa, 0xFFC80030L, "RTC_RDAYAR", "Day alarm register", log);
		createNamedByte(fpa, 0xFFC80034L, "RTC_RMONAR", "Month alarm register", log);
		createNamedByte(fpa, 0xFFC80038L, "RTC_RCR1", "RTC control register 1", log);
		createNamedByte(fpa, 0xFFC8003CL, "RTC_RCR2", "RTC control register 2", log);
	}
	
	private static void createIntcSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "INTC", 0xFFD00000L, 0x10, true, false, log);
		createNamedWord(fpa, 0xFFD00000L, "INTC_ICR", "Interrupt control register", log);
		createNamedWord(fpa, 0xFFD00004L, "INTC_IPRA", "Interrupt priority register A", log);
		createNamedWord(fpa, 0xFFD00008L, "INTC_IPRB", "Interrupt priority register B", log);
		createNamedWord(fpa, 0xFFD0000CL, "INTC_IPRC", "Interrupt priority register C", log);
	}
	
	private static void createTmuSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "TMU", 0xFFD80000L, 0x30, true, false, log);
		createNamedByte(fpa, 0xFFD80000L, "TMU_TOCR", "Timer output control register", log);
		createNamedByte(fpa, 0xFFD80004L, "TMU_TSTR", "Timer start register", log);
		createNamedDword(fpa, 0xFFD80008L, "TMU_TCOR0", "Timer constant register 0", log);
		createNamedDword(fpa, 0xFFD8000CL, "TMU_TCNT0", "Timer counter 0", log);
		createNamedWord(fpa, 0xFFD80010L, "TMU_TCR0", "Timer control register 0", log);
		createNamedDword(fpa, 0xFFD80014L, "TMU_TCOR1", "Timer constant register 1", log);
		createNamedDword(fpa, 0xFFD80018L, "TMU_TCNT1", "Timer counter 1", log);
		createNamedWord(fpa, 0xFFD8001CL, "TMU_TCR1", "Timer control register 1", log);
		createNamedDword(fpa, 0xFFD80020L, "TMU_TCOR2", "Timer constant register 2", log);
		createNamedDword(fpa, 0xFFD80024L, "TMU_TCNT2", "Timer counter 2", log);
		createNamedWord(fpa, 0xFFD80028L, "TMU_TCR2", "Timer control register 2", log);
		createNamedDword(fpa, 0xFFD8002CL, "TMU_TCPR2", "Input capture register", log);
	}
	
	private static void createSciSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "SCI", 0xFFE00000L, 0x20, true, false, log);
		createNamedByte(fpa, 0xFFE00000L, "SCI_SCSMR1", "Serial mode register", log);
		createNamedByte(fpa, 0xFFE00004L, "SCI_SCBRR1", "Bit rate register", log);
		createNamedByte(fpa, 0xFFE00008L, "SCI_SCSCR1", "Serial control register", log);
		createNamedByte(fpa, 0xFFE0000CL, "SCI_SCTDR1", "Transmit data register", log);
		createNamedByte(fpa, 0xFFE00010L, "SCI_SCSSR1", "Serial status register", log);
		createNamedByte(fpa, 0xFFE00014L, "SCI_SCRDR1", "Receive data register", log);
		createNamedByte(fpa, 0xFFE00018L, "SCI_SCSCMR1", "Smart card mode register", log);
		createNamedByte(fpa, 0xFFE0001CL, "SCI_SCSPTR1", "Serial port register", log);
	}
	
	private static void createScifSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "SCIF", 0xFFE80000L, 0x28, true, false, log);
		createNamedWord(fpa, 0xFFE80000L, "SCIF_SCSMR2", "Serial mode register", log);
		createNamedByte(fpa, 0xFFE80004L, "SCIF_SCBRR2", "Bit rate register", log);
		createNamedWord(fpa, 0xFFE80008L, "SCIF_SCSCR2", "Serial control register", log);
		createNamedByte(fpa, 0xFFE8000CL, "SCIF_SCFTDR2", "Transmit FIFO data register", log);
		createNamedWord(fpa, 0xFFE80010L, "SCIF_SCFSR2", "Serial status register", log);
		createNamedByte(fpa, 0xFFE80014L, "SCIF_SCFRDR2", "Receive FIFO data register", log);
		createNamedWord(fpa, 0xFFE80018L, "SCIF_SCFCR2", "FIFO control register", log);
		createNamedWord(fpa, 0xFFE8001CL, "SCIF_SCFDR2", "FIFO data count register", log);
		createNamedWord(fpa, 0xFFE80020L, "SCIF_SCSPTR2", "Serial port register", log);
		createNamedWord(fpa, 0xFFE80024L, "SCIF_SCLSR2", "Line status register", log);
	}
	
	private static void createHudiSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "HUDI", 0xFFF00000L, 0x0C, true, false, log);
		createNamedWord(fpa, 0xFFF00000L, "HUDI_SDIR", "Instruction register", log);
		createNamedDword(fpa, 0xFFF00008L, "HUDI_SDDR", "Data register", log);
	}
	
	private static void createNamedByte(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log) {
		Address addr = fpa.toAddr(address);
		
		try {
			fpa.createByte(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
		
		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
}
	
	private static void createNamedWord(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log) {
		Address addr = fpa.toAddr(address);
		
		try {
			fpa.createWord(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
		
		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
}
	
	private static void createNamedDword(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log) {
		Address addr = fpa.toAddr(address);
		
		try {
			fpa.createDWord(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
		
		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	private static void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
