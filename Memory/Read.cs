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
		/// Reads a single, fixed-size value of type <typeparamref name="T"/> from the specified memory address.
		/// </summary>
		/// <typeparam name="T">The unmanaged value type to read (e.g., <see cref="int"/>, <see cref="float"/>, or a custom structural struct).</typeparam>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <returns>The value read from the target process memory, or <see langword="default"/> if the address fails validation or the read operation fails.</returns>
		public T Read<T>(nint address) where T : unmanaged
		{
			T value = default;
			Span<T> valueSpan = MemoryMarshal.CreateSpan(ref value, 1);

			Read(address, valueSpan);
			return value;
		}

		/// <summary>
		/// Reads a fixed number of elements from the specified memory address and allocates a new array containing the data.
		/// </summary>
		/// <typeparam name="T">The unmanaged element type of the array.</typeparam>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <param name="length">The total number of elements to read from memory.</param>
		/// <returns>A newly allocated array containing the elements read from memory; or an empty array if <paramref name="length"/> is zero/negative or the validation fails.</returns>
		public T[] Read<T>(nint address, int length) where T : unmanaged
		{
			if (length <= 0)
				return [];

			T[] value = new T[length];

			Read(address, value.AsSpan());
			return value;
		}

		/// <summary>
		/// Reads memory from the specified address directly into an existing, pre-allocated buffer or span without causing heap allocations.
		/// </summary>
		/// <typeparam name="T">The unmanaged element type of the destination buffer.</typeparam>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <param name="buffer">The destination span where the retrieved memory bytes will be directly written.</param>
		/// <returns><see langword="true"/> if the memory was successfully read and copied into the buffer; otherwise, <see langword="false"/>.</returns>
		public bool Read<T>(nint address, Span<T> buffer) where T : unmanaged
		{
			if (buffer.IsEmpty) return false;

			Span<byte> byteSpan = MemoryMarshal.AsBytes(buffer);
			var totalBytes = byteSpan.Length;

			if (address < 0x10000 || (ulong)address > 0x7FFFFFFEFFFF || (ulong)address + (ulong)totalBytes > 0x7FFFFFFEFFFF)
				return false;

			return ReadProcessMemory(procHnd, address, byteSpan, totalBytes, 0);
		}

		/// <summary>
		/// Reads a string from a specific memory address.
		/// </summary>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <param name="length">The maximum number of bytes to read from memory.</param>
		/// <param name="stringEncoding">The character encoding type to use. Defaults to <see cref="Encoding.UTF8"/> if null.</param>
		/// <param name="zeroTerminated">Whether the string should truncate at the first null-terminator (0x00) found.</param>
		/// <returns>The decoded string value read from the target memory address, or an empty string if reading fails.</returns>
		public string ReadString(nint address, int length, Encoding? stringEncoding = null, bool zeroTerminated = true)
		{
			byte[] bytes = Read<byte>(address, length);
			if (bytes.Length == 0)
				return string.Empty;

			stringEncoding ??= Encoding.UTF8;

			if (zeroTerminated)
			{
				int nullIndex = Array.IndexOf(bytes, (byte)0);

				if (nullIndex >= 0)
					return stringEncoding.GetString(bytes.AsSpan(0, nullIndex));
			}

			//return zeroTerminated ? stringEncoding.GetString(bytes).Split('\0')[0] : stringEncoding.GetString(bytes);
			return stringEncoding.GetString(bytes);
		}

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
		public nint ScanMemory(string signature, nint startAddress = 0)
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
								return mbi.BaseAddress + i; // Add match to results list.
							}
						}
					}
				}

				// Advance cleanly to the next memory chunk boundary
				currentAddress = (nint)(mbi.BaseAddress + mbi.RegionSize);
			}
			return 0;
		}
	}
}

