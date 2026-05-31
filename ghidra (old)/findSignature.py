# @category N64
# @keybinding 
# @menupath 
# @toolbar 

# This is a Ghidra python script used to label functions in the text section of a 64DD ROM based on offsets obtained from the nm command. The offsets are added to the base address of the text section to create labels for the functions.

from ghidra.program.model.symbol import SourceType

# Base memory address where the text section starts in Ghidra
# currentProgram is injected by Ghidra's Jython runtime.
base_addr = currentProgram.getImageBase()  # noqa: F821

# Dictionary of offsets and names from the nm command
symbols = {
    0x00000038: "n64dd_create_manager",
    0x00003598: "n64dd_LeoReadWrite_READ",
    0x000037d8: "n64dd_LeoReadWrite_WRITE",
    0x00004570: "n64dd_get_RTC_BCD",
    0x000048c4: "n64dd_LeoRezero",
    0x0000494c: "n64dd_LeoSeek",
    0x000049dc: "n64dd_LeoSpdlMotor"
}

for offset, name in symbols.items():
    target_addr = base_addr.add(offset)
    # createLabel is injected by Ghidra's script runtime.
    createLabel(target_addr, name, True, SourceType.USER_DEFINED)  # noqa: F821
    print("Labeled %s at %s" % (name, target_addr))
