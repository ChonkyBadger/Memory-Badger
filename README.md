# Memory Badger
An External Memory Editing library for C#.

## Memory
- bool Attach(string processName)
- bool Close()

## Read Methods
- T Read<T>(nint address)
- T[] Read<T>(nint address, int length)
- bool Read<T>(nint address, Span<T> buffer)
- string ReadString(nint address, int length, Encoding? stringEncoding = null, bool zeroTerminated = true)

## Write Methods
- bool Write<T>(nint address, T value)
- bool Write<T>(nint address, ReadOnlySpan<T> buffer)
- bool WriteString(nint address, string value, Encoding? encoding = null )

## Code Caves
- internal bool FreeCave(nint caveAddress)

## Utility Methods
- nint GetModuleAddressByName(string name)
- nint GetAddress(nint baseAddress, int[] offsets)
- nint ScanMemory(string signature, nint startAddress = 0)
- static int[] ConvertHexStringToIntArray(string offsetString)
- static byte[] ConvertStringToBytes(string byteString)
