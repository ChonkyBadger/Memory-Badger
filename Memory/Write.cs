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
		/// Writes bytes to a specified memory address.
		/// </summary>
		/// <param name="address">Memory address to write to.</param>
		/// <param name="bytes">Bytes to write to memory address.</param>
		/// <returns></returns>
		public bool WriteBytes(nint address, byte[] bytes)
		{
			if (address == 0 || address < 0x10000)
			{
				return false;
			}

			return WriteProcessMemory(procHnd, address, bytes, bytes.Length, 0);
		}
		public bool WriteBytes(nint address, long[] offsets, byte[] bytes) => WriteBytes(GetCode(address, offsets), bytes);

		// Conversion methods for WriteBytes();
		public bool WriteInt(nint address, int memory) => WriteBytes(address, BitConverter.GetBytes(memory));
		public bool WriteInt(nint address, long[] offsets, int memory) => WriteInt(GetCode(address, offsets), memory);

		public bool WriteLong(nint address, long memory) => WriteBytes(address, BitConverter.GetBytes(memory));
		public bool WriteLong(nint address, long[] offsets, long memory) => WriteLong(GetCode(address, offsets), memory);

		public bool WriteFloat(nint address, float memory) => WriteBytes(address, BitConverter.GetBytes(memory));
		public bool WriteFloat(nint address, long[] offsets, float memory) => WriteFloat(GetCode(address, offsets), memory);

		// Code Cave Methods
		/// <summary>
		/// Creates a code cave in memory and automatically creates a JMP to the cave where the bytes replaced are.
		/// There should be at least 5 bytes replaced to make room for the JMP instruction.
		/// Automatically creates a JMP back to the original code at the end of the cave bytes.
		/// </summary>
		/// <param name="address">Address you are jumping to the cave from.</param>
		/// <param name="bytes">Bytes to automatically write from the start of the cave.</param>
		/// <param name="bytesReplaced">Number of bytes being replaced.</param>
		/// <param name="size">Side of the memory region used for the cave.</param>
		/// <returns>The starting memory address of the code cave.</returns>
		public nint CreateCodeCave(nint address, byte[] bytes, int bytesReplaced, int size = 2048)
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

				byte[] caveBytes = new byte[5 + bytes.Length];
				offset = (int)((long)address + jmpBytes.Length - ((long)caveAddress + bytes.Length) - 5);

				bytes.CopyTo(caveBytes, 0);

				caveBytes[bytes.Length] = 0xE9;
				BitConverter.GetBytes(offset).CopyTo(caveBytes, bytes.Length + 1);

				WriteBytes(caveAddress, caveBytes);
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
		/// <param name="size">Side of the memory region used for the cave.</param>
		/// <returns>The starting memory address of the code cave.</returns>
		public nint CreateCodeCave(nint address, string bytes, int bytesReplaced, int size = 2048)
			=> CreateCodeCave(address, ConvertStringToBytes(bytes), bytesReplaced, size);

		/// <summary>
		/// Creates a code cave in memory and automatically creates a JMP to the cave where the bytes replaced are.
		/// There should be at least 5 bytes replaced to make room for the JMP instruction.
		/// Does not JMP back to the original code automatically, this must be done manually.
		/// </summary>
		/// <param name="address">Address you are jumping to the cave from.</param>
		/// <param name="bytesReplaced">Number of bytes being replaced.</param>
		/// <param name="size">Side of the memory region used for the cave.</param>
		/// <returns>The starting memory address of the code cave.</returns>
		public nint CreateCodeCave(nint address, int bytesReplaced, int size = 2048)
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

				byte[] caveBytes = new byte[5];
				offset = (int)((long)address + jmpBytes.Length - (caveAddress) - 5);

				WriteBytes(address, jmpBytes);
			}
			return caveAddress;
		}

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
