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
		/// <param name="failFast">Stops the scan after the first match and returns that result.</param>
		/// <returns>List contining address found matching provided byte signature.
		/// If the scan was good, it is usually the first address.</returns>
		public List<nint> ScanMemory(string signature, nint startAddress = 0, bool failFast = true)
		{
			// Wildcard mask.
			string[] splitString = signature.Split(' ', StringSplitOptions.RemoveEmptyEntries); // FF FF > [FF, FF].
			bool[] mask = new bool[splitString.Length];
			byte[] bytes = new byte[splitString.Length];

			for (int i = 0; i < splitString.Length; i++)
			{
				var s = splitString[i];
				if (s == "??" || s == "?" || s == "0")
				{
					mask[i] = true;
					bytes[i] = 0x00; // Placeholder - Wildcard.
				}
				else
				{
					mask[i] = false;
					bytes[i] = Convert.ToByte(splitString[i], 16);
				}
			}

			List<nint> results = [];

			// Pre-allocate buffer outside the loop to eliminate Garbage Collection lag
			byte[] buffer = new byte[1024 * 1024 * 2];
			int bytesRead = 0;

			int patternLength = bytes.Length;
			int bufferLength = buffer.Length;

			// Keep track of the actual current scanning pointer
			nint currentAddress = startAddress;

			// Iterate through all memory regions for signature.
			while (VirtualQueryEx(procHnd, currentAddress,
				out MEMORY_BASIC_INFORMATION mbi,
				Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != 0)
			{
				if (mbi.State == MEM_COMMIT &&
				   (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == 0x20))
				{
					// Resize pool only if a rare chunk exceeds 2MB
					if ((int)mbi.RegionSize > bufferLength)
					{
						buffer = new byte[(int)mbi.RegionSize];
					}

					if (ReadProcessMemory(procHnd, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out bytesRead))
					{
						// Calculate our internal starting point inside this buffer.
						// If currentAddress is mid-page, this forces the search to skip the beginning of the buffer.
						int startOffset = 0;
						if (currentAddress > mbi.BaseAddress)
						{
							startOffset = (int)(currentAddress - mbi.BaseAddress);
						}

						int limit = bytesRead - patternLength;

						// Begin loop from startOffset instead of blindly starting at 0
						for (int i = startOffset; i <= limit; i++)
						{
							if (buffer[i] != bytes[0])
							{
								continue; // Skips to next iteration if does not match.
							}

							bool match = true;
							for (int j = 1; j < patternLength; j++)
							{
								// Your clean, simplified wildcard check
								if (!mask[j] && buffer[i + j] != bytes[j])
								{
									match = false;
									break;
								}
							}
							if (match)
							{
								results.Add(mbi.BaseAddress + i); // Add match to results list.

								if (failFast) 
									return results;
							}
						}
					}
				}

				// Advance cleanly to the next memory chunk boundary
				currentAddress = (nint)(mbi.BaseAddress + mbi.RegionSize);
			}
			return results;
		}

		/*
		public List<nint> ScanMemory(string signature, nint startAddress = 0)
		{
			// Wildcard mask.
			string[] splitString = signature.Split(" "); // FF FF > [FF, FF].
			bool[] mask = new bool[splitString.Length];
			byte[] bytes = new byte[splitString.Length];

			for (int i = 0; i < splitString.Length; i++)
			{
				var s = splitString[i];
				if (s == "??" || s == "?" || s == "0")
				{
					mask[i] = true;
					bytes[i] = 0x00; // Placeholder - Wildcard.
				}
				else
				{
					mask[i] = false;
					bytes[i] = Convert.ToByte(splitString[i], 16);
				}
			}

			List<nint> results = new();

			int bytesRead = 0;

			// Iterate through all memory regions for signature.
			while (VirtualQueryEx(procHnd, startAddress, 
				out MEMORY_BASIC_INFORMATION mbi, 
				Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != 0)
			{
				if (mbi.State == MEM_COMMIT && (mbi.Protect & WRITABLE_PROTECT) != 0)
				{
					byte[] buffer = new byte[(int)mbi.RegionSize];
					if (ReadProcessMemory(procHnd, mbi.BaseAddress, buffer, buffer.Length, out bytesRead))
					{
						// Only read inside boundaries
						for (int i = 0; i < bytesRead - bytes.Length; i++)
						{
							bool match = true;
							for (int j = 0; j < bytes.Length; j++)
							{
								// Check bytes compared to our signature and ignore wildcards (0)
								if (!mask[j] && buffer[i + j] != bytes[j])
								{
									match = false;
									break;
								}
							}
							if (match)
							{
								results.Add(mbi.BaseAddress + i); // Add match to results list.
							}
						}
					}
				}
				startAddress = new nint(startAddress + mbi.RegionSize);
			}
			return results;
		}*/
	}
}

