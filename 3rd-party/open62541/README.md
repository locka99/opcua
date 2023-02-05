This is a simple C++ application written against the C open62541 library. 

Setup depends on your environment but essentially:

1. CMake - https://cmake.org/
2. Python 3 - https://www.python.org
3. C/C++ toolchain

Then:

```
git clone https://github.com/open62541/open62541.git -b 1.0
mkdir build
cd build
cmake -G "generator" ..
```

Where "generator" might be:

- "Ninja"
- "NMake Makefiles"
- "Unix Makefiles"
- "Visual Studio 17 2022"
- etc.

Depending on your operating system and environment.
