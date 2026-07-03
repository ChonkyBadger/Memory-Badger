using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Reflection.Metadata.Ecma335;
using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace MemoryBadger
{
	public partial class Memory
	{
		/// <summary>
		/// Reads a value of type T from a specific memory address. 
		/// The type must have a fixed size (e.g. No arrays or strings).
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="address">Memory Address to read from.</param>
		/// <returns></returns>
		public T Read<T>(nint address) where T : unmanaged
		{
			T value = default;
			int size = Unsafe.SizeOf<T>();

			if (address < 0x10000 || (ulong)address > 0x7FFFFFFEFFFF || (ulong)address + (ulong)size > 0x7FFFFFFEFFFF)
			{
				return value;
			}

			Span<T> valueSpan = MemoryMarshal.CreateSpan(ref value, 1);
			Span<byte> byteSpan = MemoryMarshal.AsBytes(valueSpan);
			ReadProcessMemory(procHnd, address, byteSpan, byteSpan.Length, 0);

			return value;
		}

		/// <summary>
		/// Reads an array of type T from a specific memory address. 
		/// </summary>
		/// <typeparam name="T"></typeparam>
		/// <param name="address">Memory Address to read from.</param>
		/// <param name="length">Length of the Array</param>
		/// <returns></returns>
		public T[] ReadArray<T>(nint address, int length) where T : unmanaged
		{
			T[] value = new T[length];
			var totalBytes = length * Unsafe.SizeOf<T>();

			if (address < 0x10000 || (ulong)address > 0x7FFFFFFEFFFF || (ulong)address + (ulong)totalBytes > 0x7FFFFFFEFFFF)
			{
				return value;
			}

			var byteSpan = MemoryMarshal.AsBytes(value.AsSpan());
			ReadProcessMemory(procHnd, address, byteSpan, totalBytes, 0);

			return value;
		}

		/// <summary>
		/// Reads a string from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <param name="length">Length of the string in bytes.</param>
		/// <param name="stringEncoding">Encoding type to use for the string. 
		/// If left as null, it will be set to UTF8 by default.</param>
		/// <param name="zeroTerminated">Whether or not it should terminate upon reading
		/// a zero (0x00). This usually indicates the end of a string.</param>
		/// <returns>String value read from memory address.</returns>
		public string ReadString(nint address, int length, Encoding? stringEncoding = null, bool zeroTerminated = true)
		{
			var bytes = ReadArray<byte>(address, length);

			stringEncoding ??= Encoding.UTF8;

			if (bytes.Length > 0)
				return zeroTerminated ? stringEncoding.GetString(bytes).Split('\0')[0] : stringEncoding.GetString(bytes);
			else return string.Empty;
		}
		/// <summary>
		/// Reads a string from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address..</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="length">Length of the string in bytes.</param>
		/// <param name="stringEncoding">Encoding type to use for the string. 
		/// If left as null, it will be set to UTF8 by default.</param>
		/// <param name="zeroTerminated">Whether or not it should terminate upon reading
		/// a zero (0x00). This usually indicates the end of a string.</param>
		/// <returns>String value read memory address.</returns>
		public string ReadString(nint address, long[] offsets, int length,
			Encoding? stringEncoding = null, bool zeroTerminated = true)
			=> ReadString(GetCode(address, offsets), length, stringEncoding, zeroTerminated);

		#region LEGACY SUPPORT
		/// <summary>
		/// Reads bytes from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from..</param>
		/// <param name="length">Number of bytes to read.</param>
		/// <returns>Bytes at memory address.</returns>
		public byte[] ReadBytes(nint address, int length) 
			=> ReadArray<byte>(address, length);
		/// <summary>
		/// Reads bytes from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="length">Number of bytes to read.</param>
		/// <returns>Bytes at memory address.</returns>
		public byte[] ReadBytes(nint address, long[] offsets, int length)
			=> ReadArray<byte>(GetCode(address, offsets), length);

		// Conversion methods for ReadBytes();
		/// <summary>
		/// Reads a 32-bit integer from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <returns>Integer value at memory address.</returns>
		public int ReadInt(nint address) => Read<int>(address);
		/// <summary>
		/// Reads a 32-bit integer value from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <returns>Integer value at memory address.</returns>
		public int ReadInt(nint address, long[] offsets) => ReadInt(GetCode(address, offsets));

		/// <summary>
		/// Reads a 64-bit integer value from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <returns>64-bit integer value at memory address.</returns>
		public long ReadLong(nint address) => Read<long>(address);
		/// <summary>
		/// Reads a 64-bit integer value from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <returns>64-bit integer value at memory address.</returns>
		public long ReadLong(nint address, long[] offsets) => ReadLong(GetCode(address, offsets));

		/// <summary>
		/// Reads a single-precision floating point value from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <param name="round">Whether to round to a specified number of places.</param>
		/// <param name="digits">Number of decimal places to round to (if round is true).</param>
		/// <returns>Single-precision floating point value at memory address.</returns>
		public float ReadFloat(nint address, bool round = true, int digits = 2)
		{
			var value = Read<float>(address);

			if (round)
				return (float)Math.Round(value, digits);
			else return value;
		}

		/// <summary>
		/// Reads a single-precision floating point value from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="round">Whether to round to a specified number of places.</param>
		/// <param name="digits">Number of decimal places to round to (if round is true).</param>
		/// <returns>Single-precision floating point value at memory address.</returns>
		public float ReadFloat(nint address, long[] offsets, bool round = true, int digits = 2)
			=> ReadFloat(GetCode(address, offsets), round, digits);

		/// <summary>
		/// Reads a double-precision floating point value from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <param name="round">Whether to round to a specified number of places.</param>
		/// <param name="digits">Number of decimal places to round to (if round is true).</param>
		/// <returns>Double-precision floating point value at memory address.</returns>
		public double ReadDouble(nint address, bool round = true, int digits = 2)
		{
			var value = Read<double>(address);

			if (round)
				return (double)Math.Round(value, digits);
			else return value;
		}
		/// <summary>
		/// Reads a double-precision floating point value from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="round">Whether to round to a specified number of places.</param>
		/// <param name="digits">Number of decimal places to round to (if round is true).</param>
		/// <returns>Double-precision floating point value at memory address.</returns>
		public double ReadDouble(nint address, long[] offsets, bool round = true, int digits = 2)
			=> ReadDouble(GetCode(address, offsets), round, digits);

		/// <summary>
		/// Reads bytes from a specific memory address and returns them as a BitArray.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <param name="byteLength">Number of bytes to read.</param>
		/// <returns>BitArray from the bytes read.</returns>
		public BitArray ReadBits(nint address, int byteLength) =>
			new(ReadArray<byte>(address, byteLength));
		#endregion

		// AOB-Pattern scanning.
		/// <summary>
		/// Scans for an array of bytes, returning a list of results. 
		/// To avoid bad results, try to make the array of bytes as unique as possible. 
		/// </summary>
		/// <param name="signature">Bytes to scan for in string format. (e.g. "A1 C3 08 ?? FF")
		/// "??", "?" and "0" can be used to indicate a "wildcard" which can be any value. 
		/// "00" is not treated as a wildcard</param>
		/// <param name="startAddress">Base address of memory module to start scan from.</param>
		/// <returns>List contining address found matching provided byte signature.
		/// If the scan was good, it is usually the first address.</returns>
		public List<nint> ScanMemory(string signature, nint startAddress = 0)
		{
			if (string.IsNullOrWhiteSpace(signature))
				return new List<nint>();

			// 1. Split the string by spaces to isolate individual hex bytes and wildcards
			string[] tokens = signature.Split(' ', StringSplitOptions.RemoveEmptyEntries);

			byte[] pattern = new byte[tokens.Length];
			bool[] mask = new bool[tokens.Length]; // true = check this byte, false = wildcard (skip).

			// 2. Loop through the tokens to build both arrays simultaneously/
			for (int i = 0; i < tokens.Length; i++)
			{
				if (tokens[i] == "??" || tokens[i] == "?" || tokens[i] == "0")
				{
					pattern[i] = 0x00; // Placeholder byte for wildcards.
					mask[i] = false;   // Rule: Skip checking this index entirely.
				}
				else
				{
					pattern[i] = Convert.ToByte(tokens[i], 16);
					mask[i] = true;    // Rule: Must match this byte value exactly.
				}
			}

			// 3. Forward the finalized data straight to your optimized core scanner loop.
			return ScanMemory(pattern, mask, startAddress);
		}

		private List<nint> ScanMemory(byte[] pattern, bool[] mask, nint startAddress = 0)
		{
			List<nint> results = new();

			// REUSABLE BUFFER POOL
			// Instead of allocating inside the loop, we reuse a single array.
			// It grows dynamically only if a memory region is larger than the current pool.
			byte[] sharedBuffer = new byte[4096];

			nint currentAddress = startAddress;
			int bytesRead = 0;

			while (VirtualQueryEx(procHnd, currentAddress, out MEMORY_BASIC_INFORMATION mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
			{
				// 1. Check if the page state is committed using your global class constant
				bool isCommitted = mbi.State == MEM_COMMIT;

				// 2. Exact Protection Filtering using your class constants
				// Ensures we only process memory regions that Windows explicitly allows us to read from.
				bool isReadable = mbi.Protect == PAGE_READONLY ||
								  mbi.Protect == PAGE_READWRITE ||
								  mbi.Protect == PAGE_EXECUTE_READWRITE;

				if (isCommitted && isReadable)
				{
					int regionSize = (int)mbi.RegionSize;

					// Dynamically grow the single shared buffer if we hit an exceptionally large region
					if (sharedBuffer.Length < regionSize)
					{
						Array.Resize(ref sharedBuffer, regionSize);
					}

					// Create a temporary Span window over our shared buffer pool
					Span<byte> bufferSpan = sharedBuffer.AsSpan(0, regionSize);

					// Read the full page directly into our Span window (Zero Allocations!)
					if (ReadProcessMemory(procHnd, mbi.BaseAddress, bufferSpan, regionSize, out bytesRead) && bytesRead > 0)
					{
						// Create a localized slice of exactly how many bytes Windows successfully grabbed
						ReadOnlySpan<byte> activeMemory = bufferSpan[..bytesRead];
						int scanLimit = bytesRead - pattern.Length;

						// 3. BLISTERING FAST SCAN LOOP OVER THE SPAN BOUNDS
						for (int i = 0; i <= scanLimit; i++)
						{
							bool isMatch = true;

							for (int j = 0; j < pattern.Length; j++)
							{
								// 🌟 THE TRUE MASK FIX: 
								// If mask[j] is false, it's a wildcard -> skip checking and continue.
								// If mask[j] is true, it evaluates actual bytes. Real 0x00 bytes work perfectly!
								if (mask[j] && activeMemory[i + j] != pattern[j])
								{
									isMatch = false;
									break; // Immediate early exit on the very first byte mismatch
								}
							}

							if (isMatch)
							{
								results.Add(mbi.BaseAddress + i); // Track successful match address
							}
						}
					}
				}

				// Safely advance past the current memory section to find the next page block layout
				currentAddress = mbi.BaseAddress + (nint)mbi.RegionSize;
			}

			return results;
		}
	}
}
