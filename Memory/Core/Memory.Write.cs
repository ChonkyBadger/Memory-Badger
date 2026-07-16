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
		/// Writes a single, fixed-size value of type <typeparamref name="T"/> to the specified memory address.
		/// </summary>
		/// <typeparam name="T">The unmanaged value type to write (e.g., <see cref="int"/>, <see cref="float"/>, or a custom structural struct).</typeparam>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <param name="value">The data value to write into the target process memory space.</param>
		/// <returns><see langword="true"/> if the value was successfully written; otherwise, <see langword="false"/>.</returns>
		public bool Write<T>(nint address, T value) where T : unmanaged
		{
			ReadOnlySpan<T> valueSpan = MemoryMarshal.CreateSpan(ref value, 1);
			return Write(address, valueSpan);
		}

		/// <summary>
		/// Writes a sequence of elements from a read-only buffer to the specified memory address.
		/// </summary>
		/// <typeparam name="T">The unmanaged element type of the buffer data.</typeparam>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <param name="buffer">The read-only data span to write. Natively accepts arrays, array slices, and stack-allocated blocks.</param>
		/// <returns><see langword="true"/> if the buffer contents were successfully written to the target process; otherwise, <see langword="false"/>.</returns>
		public bool Write<T>(nint address, ReadOnlySpan<T> buffer) where T : unmanaged
		{
			if (buffer.IsEmpty) return false;


			ReadOnlySpan<byte> byteSpan = MemoryMarshal.AsBytes(buffer);
			var totalBytes = byteSpan.Length;

			if (address < 0x10000 || (ulong)address > 0x7FFFFFFEFFFF || (ulong)address + (ulong)totalBytes > 0x7FFFFFFEFFFF)
			{
				return false;
			}

			return WriteProcessMemory(procHnd, address, byteSpan, totalBytes, 0);
		}

		/// <summary>
		/// Writes a string to a specific memory address and appends a null-terminator.
		/// </summary>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <param name="value">The string value to write into the target process.</param>
		/// <param name="encoding">The character encoding type to use. Defaults to <see cref="Encoding.UTF8"/> if null.</param>
		/// <returns><see langword="true"/> if the string and its null-terminator were successfully written; otherwise, <see langword="false"/>.</returns>
		public bool WriteString(nint address, string value, Encoding? encoding = null)
		{
			encoding ??= Encoding.UTF8;

			if (string.IsNullOrEmpty(value))
				return Write<byte>(address, 0);

			byte[] stringBytes = encoding.GetBytes(value);
			var finalBuffer = new byte[stringBytes.Length + 1];

			Buffer.BlockCopy(stringBytes, 0, finalBuffer, 0, stringBytes.Length);

			return Write(address, finalBuffer);
		}
	}
}