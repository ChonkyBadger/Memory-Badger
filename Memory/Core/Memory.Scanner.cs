using MemoryBadger.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Markup;

namespace MemoryBadger
{
	public partial class Memory
	{
		/// <summary>
		/// Scans for an array of bytes, returning a list of results. 
		/// To avoid bad results, try to make the array of bytes as unique as possible. 
		/// </summary>
		/// <param name="signature">Bytes to scan for for passed in a <see cref="ReadOnlySpan{T}"/>.
		/// Null bytes are treated as wildcards. Example: [0x48, 0x8B, null, null, 0x48]</param>
		/// <param name="startAddress">Base address of memory module to start scan from.</param>
		/// <returns>List contining address found matching provided byte signature.
		/// If the scan was good, it is usually the first address.</returns>
		public nint ScanMemory(ReadOnlySpan<byte?> signature, nint startAddress = 0)
		{
			if (signature.Length == 0)
				return 0;

			// Keep your excellent pre-allocated 2MB buffer strategy
			byte[] buffer = new byte[1024 * 1024 * 2];
			int patternLength = signature.Length;
			int bufferLength = buffer.Length;

			nint currentAddress = startAddress;

			// Cache the first byte data to maximize CPU register optimization
			byte? firstByteNullable = signature[0];
			byte firstByte = firstByteNullable ?? 0;
			bool firstIsWildcard = firstByteNullable == null;

			while (VirtualQueryEx(procHnd, currentAddress,
				out MEMORY_BASIC_INFORMATION mbi,
				Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != 0)
			{
				if (mbi.State == MEM_COMMIT &&
				   (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == 0x20))
				{
					// Keep your safety auto-resize block
					if ((int)mbi.RegionSize > bufferLength)
					{
						buffer = new byte[(int)mbi.RegionSize];
						bufferLength = buffer.Length;
					}

					if (ReadProcessMemory(procHnd, mbi.BaseAddress, buffer, (int)mbi.RegionSize, out int bytesRead))
					{
						int startOffset = 0;
						if (currentAddress > mbi.BaseAddress)
						{
							startOffset = (int)(currentAddress - mbi.BaseAddress);
						}

						int limit = bytesRead - patternLength;

						// Create a zero-allocation Span view of the valid memory read from the process
						ReadOnlySpan<byte> searchSpan = buffer.AsSpan(0, bytesRead);
						int i = startOffset;

						while (i <= limit)
						{
							// If the first byte is a concrete value (not a wildcard '?'), run the vector engine
							if (!firstIsWildcard)
							{
								// HARDWARE ACCELERATION: Sweep memory 16 to 32 bytes at a time using CPU SIMD registers
								int nextIdx = searchSpan[i..].IndexOf(firstByte);
								if (nextIdx == -1)
									break; // First byte was not found anywhere in the remaining page buffer

								i += nextIdx;
								if (i > limit)
									break;
							}

							// Vector engine alignment achieved; quickly validate the remaining signature sequence
							bool match = true;
							for (int j = 1; j < patternLength; j++)
							{
								if (signature[j] != null && searchSpan[i + j] != signature[j])
								{
									match = false;
									break;
								}
							}

							if (match)
							{
								return mbi.BaseAddress + i; // Match found! Return the absolute remote address
							}

							i++; // Shift forward by one if the complete pattern sequence failed
						}
					}
				}

				// Advance cleanly to the next memory chunk boundary
				currentAddress = (nint)(mbi.BaseAddress + mbi.RegionSize);
			}
			return 0;
		}

		/// <summary>
		/// Scans for an array of bytes, returning a list of results. 
		/// To avoid bad results, try to make the array of bytes as unique as possible. 
		/// </summary>
		/// <param name="signature">Bytes to scan for for passed in a <see cref="string"/>.
		/// ?? and ? are treated as wildcards. Example: "48 8B ?? ?? 48"</param>
		/// <param name="startAddress">Base address of memory module to start scan from.</param>
		/// <returns>List contining address found matching provided byte signature.
		/// If the scan was good, it is usually the first address.</returns>
		public nint ScanMemory(ReadOnlySpan<char> signature, nint startAddress = 0)
		{
			int maxByteCount = (signature.Length + 1) / 3;

			Span<byte?> buffer = maxByteCount <= 512
				? stackalloc byte?[maxByteCount] : new byte?[maxByteCount];

			int actualLength = Utility.ParseHexStringAsNullableBytes(signature, buffer);

			return ScanMemory(buffer[..actualLength], startAddress);
		}
	}
}