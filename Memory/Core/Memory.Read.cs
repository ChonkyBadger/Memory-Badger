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
using MemoryBadger.Utilities;


namespace MemoryBadger;

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
	/// <param name="maxChars">The maximum number of characters to read.</param>
	/// <param name="stringEncoding">The character encoding type to use. Defaults to <see cref="Encoding.UTF8"/> if null.</param>
	/// <param name="zeroTerminated">Whether the string should truncate at the first null-terminator (0x00) found.</param>
	/// <returns>The decoded string value read from the target memory address, or an empty string if reading fails.</returns>
	public string ReadString(nint address, int maxChars = 128, Encoding? stringEncoding = null, bool zeroTerminated = true)
	{
		if (address == 0) return string.Empty;

		stringEncoding ??= Encoding.UTF8;

		var byteList = new List<byte>();
		int chunkSize = 16; // 16-byte chunks prevent page-boundary RPM failures

		for (int offset = 0; offset < maxChars; offset += chunkSize)
		{
			int toRead = Math.Min(chunkSize, maxChars - offset);
			byte[] chunk = Read<byte>(address + offset, toRead);

			// If memory read failed (unmapped RAM page), stop reading
			if (chunk.Length == 0) break;

			if (zeroTerminated)
			{
				// Check if this chunk contains the null terminator \0
				int nullPos = Array.IndexOf(chunk, (byte)0);
				if (nullPos >= 0)
				{
					// Add bytes up to the null terminator and finish!
					for (int i = 0; i < nullPos; i++)
					{
						byteList.Add(chunk[i]);
					}
					break;
				}
			}

			// Append the chunk bytes and keep reading
			byteList.AddRange(chunk);
		}

		if (byteList.Count == 0) return string.Empty;

		return stringEncoding.GetString(byteList.ToArray());
	}
	/*
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
	}*/
}