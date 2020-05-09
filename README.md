# About
Nintendo DS loader module for IDA Pro 7.whatever on macos (64 bit)

# Macos Installation
- Install the IDA SDK(tm)
- Create a build folder
- Generate the makefile using CMake: cmake -DIDASDK_FOLDER=/path/to/ida/sdk /path/to/source
- Compile the plugin using make
- Copy the nds.dylib file to IDA_INSTALL/loaders

# Credits
- Dennis Elser: original loader.
- Franck Charlet: other fixes.
- EliseZeroTwo: macos 64 bit support
