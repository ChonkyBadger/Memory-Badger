using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;

namespace MemoryBadger
{
	public partial class Memory
	{
		/// <summary>
		/// Writes bytes to a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to write to.</param>
		/// <param name="bytes">Bytes to write to memory address.</param>
		/// <returns>True if successful.</returns>
		public bool WriteBytes(nint address, byte[] bytes)
		{
			if (address == 0 || address < 0x10000)
			{
				return false;
			}

			return WriteProcessMemory(procHnd, address, bytes, bytes.Length, 0);
		}
		/// <summary>
		/// Writes bytes to memory from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="bytes">Bytes to write to memory address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <returns>True if successful.</returns>
		public bool WriteBytes(nint address, long[] offsets, byte[] bytes) 
			=> WriteBytes(GetCode(address, offsets), bytes);

		// Conversion methods for WriteBytes();
		/// <summary>
		/// Writes an integer value to a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to write to.</param>
		/// <param name="memory">Integer value to write to memory.</param>
		/// <returns>True if successful</returns>
		public bool WriteInt(nint address, int memory) 
			=> WriteBytes(address, BitConverter.GetBytes(memory));
		/// <summary>
		/// Writes an integer value to memory from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="memory">Integer value to write to memory.</param>
		/// <returns>True if successful.</returns>
		public bool WriteInt(nint address, long[] offsets, int memory) 
			=> WriteInt(GetCode(address, offsets), memory);

		/// <summary>
		/// Writes a 64-bit integer value to a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to write to.</param>
		/// <param name="memory">Value to write to memory.</param>
		/// <returns>True if successful</returns>
		public bool WriteLong(nint address, long memory) 
			=> WriteBytes(address, BitConverter.GetBytes(memory));
		/// <summary>
		/// Writes a 64-bit integer value to memory from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="memory">Value to write to memory.</param>
		/// <returns>True if successful.</returns>
		public bool WriteLong(nint address, long[] offsets, long memory) 
			=> WriteLong(GetCode(address, offsets), memory);

		/// <summary>
		/// Writes a single-precision floating point value to a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to write to.</param>
		/// <param name="memory">Value to write to memory.</param>
		/// <returns>True if successful</returns>
		public bool WriteFloat(nint address, float memory) 
			=> WriteBytes(address, BitConverter.GetBytes(memory));
		/// <summary>
		/// Writes a single-precision floating point value to memory from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="memory">Value to write to memory.</param>
		/// <returns>True if successful.</returns>
		public bool WriteFloat(nint address, long[] offsets, float memory) 
			=> WriteFloat(GetCode(address, offsets), memory);

		/// <summary>
		/// Writes a double-precision floating point value to a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to write to.</param>
		/// <param name="memory">Value to write to memory.</param>
		/// <returns>True if successful</returns>
		public bool WriteDouble(nint address, double memory) 
			=> WriteBytes(address, BitConverter.GetBytes(memory));
		/// <summary>
		/// Writes a double-precision floating point value to memory from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="memory">Value to write to memory.</param>
		/// <returns>True if successful.</returns>
		public bool WriteDouble(nint address, long[] offsets, float memory) 
			=> WriteDouble(GetCode(address, offsets), memory);

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

					WriteBytes(caveAddress, caveBytes);
				}

				WriteBytes(address, jmpBytes);
			}

			return caveAddress;
		}
		/// <summary>
		/// Creates a code cave in memory and automatically creates a JMP to the cave where the bytes replaced are.
		/// There should be at least 5 bytes replaced to make room for the JMP instruction.
		/// Automatically creates a JMP back to the original code at the end of the cave bytes.
		/// </summary>
		/// <param name="address">Address you are jumping to the cave from.</param>
		/// <param name="bytes">Bytes to automatically write from the start of the cave.</param>
		/// <param name="bytesReplaced">Number of bytes being replaced.</param>
		/// <param name="jmpBack">Whether to create a JMP back to the original code at the end of the cave bytes.</param>
		/// <param name="size">Size of the memory region used for the cave.</param>
		/// <returns>The starting memory address of the code cave.</returns>
		public nint CreateCodeCave(nint address, string bytes, int bytesReplaced, bool jmpBack = true, int size = 4096)
			=> CreateCodeCave(address, ConvertStringToBytes(bytes), bytesReplaced, jmpBack, size);

		/// <summary>
		/// Frees up the memory region used by a code cave.
		/// </summary>
		/// <param name="caveAddress">Memory address of the cave to free.</param>
		/// <returns>True if successfully freed.</returns>
		public bool FreeCave(nint caveAddress)
		{
			var rel = VirtualFreeEx(procHnd, caveAddress, 0, 0x00008000);

			return rel;
		}
	}
}
