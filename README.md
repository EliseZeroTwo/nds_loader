# About
Nintendo DS loader module for IDA Pro 7.0

# Windows Installation
Copy ***nds.dll*** to your ***loaders*** folder.

# Linux Installation
- Install the IDA SDK
- Create a build folder
- Generate the makefile using CMake: cmake -DIDASDK=/path/to/ida/sdk /path/to/source
- Compile the plugin using make
- Copy the nds.llx file inside your IDA directory

# Credits
- Dennis Elser: original loader.
- Franck Charlet: other fixes.
