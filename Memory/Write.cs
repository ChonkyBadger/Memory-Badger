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
		public bool WriteString(nint address, string value, Encoding? encoding = null )
		{
			encoding ??= Encoding.UTF8;

			if (string.IsNullOrEmpty(value))
				return Write<byte>(address, 0);

			byte[] stringBytes = encoding.GetBytes(value);
			var finalBuffer = new byte[stringBytes.Length + 1];

			Buffer.BlockCopy(stringBytes, 0, finalBuffer, 0, stringBytes.Length);

			return Write(address, finalBuffer);
		}

		// Code Cave Methods
		/// <summary>
		/// Creates a code cave in memory and automatically creates a JMP to the cave where the bytes replaced are.
		/// There should be at least 5 bytes replaced to make room for the JMP instruction.
		/// By default, automatically creates a JMP back to the original code at the end of the cave bytes.
		/// </summary>
		/// <param name="address">Address you are jumping to the cave from.</param>
		/// <param name="bytes">Bytes to automatically write from the start of the cave.</param>
		/// <param name="bytesReplaced">Number of bytes being replaced.</param>
		/// <param name="jmpBack">Whether to create a JMP back to the original code at the end of the cave bytes.</param>
		/// <param name="size">Side of the memory region used for the cave.</param>
		/// <returns>The starting memory address of the code cave.</returns>
		public nint CreateCodeCave(nint address, byte[] bytes, int bytesReplaced, bool jmpBack = true, int size = 2048)
		{
			nint caveAddress = 0;
			nint preferred = address;

			for (var i = 0; i < 10 && caveAddress == 0; i++)
			{
				caveAddress = VirtualAllocEx(procHnd, FindFreeBlockForRegion(preferred, size), size,
					MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				if (caveAddress == 0)
					preferred = nint.Add(preferred, 0x10000);
			}

			if (caveAddress == 0)
			{
				caveAddress = VirtualAllocEx(procHnd, (nint)null, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			}

			if (caveAddress != 0)
			{
				int nopsNeeded = bytesReplaced > 5 ? bytesReplaced - 5 : 0;

				// (to - from - 5)
				int offset = (int)(caveAddress - address - 5);

				byte[] jmpBytes = new byte[5 + nopsNeeded];
				jmpBytes[0] = 0xE9;
				BitConverter.GetBytes(offset).CopyTo(jmpBytes, 1);

				for (var i = 5; i < jmpBytes.Length; i++)
				{
					jmpBytes[i] = 0x90;
				}

				if (jmpBack)
				{
					byte[] caveBytes = new byte[5 + bytes.Length];
					offset = (int)((long)address + jmpBytes.Length - ((long)caveAddress + bytes.Length) - 5);

					bytes.CopyTo(caveBytes, 0);

					caveBytes[bytes.Length] = 0xE9;
					BitConverter.GetBytes(offset).CopyTo(caveBytes, bytes.Length + 1);

					Write(caveAddress, caveBytes);
				}

				Write(address, jmpBytes);
			}

			return caveAddress;
		}

		/// <summary>
		/// Allocates an executable memory page in the target process near a preferred address,
		/// managed by a <see cref="SmartCave"/> instance to allow the creation of multiple smaller
		/// caves and hooks in a single memory allocation with ease.
		/// </summary>
		/// <param name="address">The preferred baseline address to start searching from.</param>
		/// <param name="size">The total size of the parent page to allocate. Defaults to 4096 bytes
		/// which is the size of a single page.</param>
		/// <returns>A managed <see cref="SmartCave"/> instance capable of spawning safe sub-allocations.</returns>
		/// <exception cref="InvalidOperationException">Thrown if Windows fails to allocate memory after searching.</exception>
		public SmartCave CreateSmartCave(nint address, int size = 4096)
		{
			var caveAddress = AllocateCodeCave(address, size);

			if (caveAddress != 0)
				return new SmartCave(this, caveAddress, size);
			throw new InvalidOperationException("Failed to allocate virtual memory for the smart code cave controller.");
		}

		/// <summary>
		/// Allocates an executable memory page in the target process near a preferred address,
		/// managed by a <see cref="SmartChasm"/>. This automatically creates a JMP instruction 
		/// to and from the cave.
		/// </summary>
		/// <param name="address">The preferred baseline address to start searching from.</param>
		/// <param name="bytesReplaced">The number of bytes being replaced with a JMP to the <see cref="SmartChasm"/>.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="SmartChasm"/>.</param>
		/// <param name="size">The total size of the parent page to allocate. Defaults to 4096 bytes
		/// which is the size of a single page.</param>
		/// <returns>A managed <see cref="SmartCave"/> instance capable of spawning safe sub-allocations.</returns>
		/// <exception cref="InvalidOperationException">Thrown if Windows fails to allocate memory after searching.</exception>
		public SmartChasm CreateCodeCave(nint address, int bytesReplaced, ReadOnlySpan<byte> payload, int size = 4096)
		{
			var caveAddress = AllocateCodeCave(address, size);

			if (caveAddress != 0)
				return SmartChasm.CreateStandalone(this, caveAddress, address, bytesReplaced, size, payload);
			throw new InvalidOperationException("Failed to allocate virtual memory for the code cave.");
		}

		/// <summary>
		/// Allocates an executable memory page in the target process near a preferred address,
		/// managed by a <see cref="Chasm"/>. Does not automatically write any JMP instructions.
		/// to and from the cave.
		/// </summary>
		/// <param name="address">The preferred baseline address to start searching from.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="Chasm"/>.</param>
		/// <param name="size">The total size of the parent page to allocate. Defaults to 4096 bytes
		/// which is the size of a single page.</param>
		/// <returns>A managed <see cref="Chasm"/> instance capable of spawning safe sub-allocations.</returns>
		/// <exception cref="InvalidOperationException">Thrown if Windows fails to allocate memory after searching.</exception>
		public Chasm CreateCodeCave(nint address, ReadOnlySpan<byte> payload, int size = 4096)
		{
			var caveAddress = AllocateCodeCave(address, size);

			if (caveAddress != 0)
				return Chasm.CreateStandalone(this, caveAddress, size, payload);
			throw new InvalidOperationException("Failed to allocate virtual memory for the code cave.");
		}
	}
}
