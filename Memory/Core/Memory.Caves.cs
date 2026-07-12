using MemoryBadger.Caves;
using MemoryBadger.Utilities;
using System.Collections;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;

namespace MemoryBadger
{
	/// <summary>
	/// Holds all memory related methods.
	/// </summary>
	public partial class Memory
	{
		/// <summary>
		/// Allocates an executable memory page in the target process near a preferred address,
		/// managed by a <see cref="CaveManager"/> instance to allow the creation of multiple smaller
		/// caves and hooks in a single memory allocation with ease.
		/// </summary>
		/// <param name="address">The preferred baseline address to start searching from.</param>
		/// <param name="size">The total size of the parent page to allocate. Defaults to 4096 bytes
		/// which is the size of a single page.</param>
		/// <returns>A managed <see cref="CaveManager"/> instance capable of spawning safe sub-allocations.</returns>
		/// <exception cref="InvalidOperationException">Thrown if Windows fails to allocate memory after searching.</exception>
		public CaveManager CreateCaveManager(nint address, int size = 4096)
		{
			var caveAddress = AllocateCodeCave(address, size);

			if (caveAddress != 0)
				return new CaveManager(this, caveAddress, size);
			throw new InvalidOperationException("Failed to allocate virtual memory for the smart code cave controller.");
		}

		/// <summary>
		/// Allocates memory for and creates a <see cref="Detour"/>. Use <see cref="Detour.Write(nint, int, ReadOnlySpan{byte})"/>
		/// to write custom instructions. The <see cref="Detour"/> automatically writes JMP instructions to
		/// and from the Detour after writing your instructions.
		/// </summary>
		/// <param name="address">The preferred baseline address to start searching for free memory from.</param>
		/// <param name="size">The total size of the parent page to allocate. Defaults to 4096 bytes
		/// which is the size of a single page.</param>
		/// <returns>A managed <see cref="CodeCave"/> instance capable of spawning safe sub-allocations.</returns>
		/// <exception cref="InvalidOperationException">Thrown if Windows fails to allocate memory after searching.</exception>
		public Detour CreateDetour(nint address, int size = 4096)
		{
			var caveAddress = AllocateCodeCave(address, size);

			if (caveAddress != 0)
				return new Detour(this, caveAddress, size, false);
			throw new InvalidOperationException("Failed to allocate virtual memory for the code cave.");
		}

		/// <summary>
		/// Allocates memory for and creates a <see cref="Detour"/>. Automatically writes your custom payload
		/// to the detour using <see cref="Detour.Write(nint, int, ReadOnlySpan{byte})"/> The <see cref="Detour"/> 
		/// automatically writes JMP instructions to and from the Detour after writing your instructions.
		/// </summary>
		/// <param name="address">The preferred baseline address to start searching for free memory from.</param>
		/// <param name="bytesReplaced">Number of bytes that will be replaced when writing the
		/// the JMP from the original game code to the detour.</param>
		/// <param name="payload">A <see cref="ReadOnlySpan{T}"/> containing custom bytes to automatically write
		/// in the <see cref="Detour"/></param>
		/// <param name="size">The total size of the parent page to allocate. Defaults to 4096 bytes
		/// which is the size of a single page.</param>
		/// <returns>A managed <see cref="CodeCave"/> instance capable of spawning safe sub-allocations.</returns>
		/// <exception cref="InvalidOperationException">Thrown if Windows fails to allocate memory after searching.</exception>
		public Detour CreateDetour(nint address, int bytesReplaced, ReadOnlySpan<byte> payload, int size = 4096)
		{
			var detour = CreateDetour(address, size);
			detour.Write(address, bytesReplaced, payload);

			return detour;
		}

		/// <summary>
		/// Allocates memory for and creates a <see cref="CodeCave"/>. Use <see cref="CodeCave.Write(ReadOnlySpan{byte})"/>
		/// to write custom instructions.
		/// </summary>
		/// <param name="address">The preferred baseline address to start searching for free memory from.</param>
		/// <param name="size">The total size of the parent page to allocate. Defaults to 4096 bytes
		/// which is the size of a single page.</param>
		/// <returns>A managed <see cref="CodeCave"/> instance capable of spawning safe sub-allocations.</returns>
		/// <exception cref="InvalidOperationException">Thrown if Windows fails to allocate memory after searching.</exception>
		public CodeCave CreateCodeCave(nint address, int size = 4096)
		{
			var caveAddress = AllocateCodeCave(address, size);

			if (caveAddress != 0)
				return new CodeCave(this, caveAddress, size, false);
			throw new InvalidOperationException("Failed to allocate virtual memory for the code cave.");
		}

		/// <summary>
		/// Allocates memory for and creates a <see cref="CodeCave"/>. Automatically writes
		/// <paramref name="payload"/> using <see cref="CodeCave.Write(ReadOnlySpan{byte})"/>
		/// </summary>
		/// <param name="address">The preferred baseline address to start searching for free memory from.</param>
		/// <param name="payload">A <see cref="ReadOnlySpan{T}"/> containing custom bytes to autoatically write
		/// to the <see cref="CodeCave"/></param>
		/// <param name="size">The total size of the parent page to allocate. Defaults to 4096 bytes
		/// which is the size of a single page.</param>
		/// <returns>A managed <see cref="CodeCave"/> instance capable of spawning safe sub-allocations.</returns>
		/// <exception cref="InvalidOperationException">Thrown if Windows fails to allocate memory after searching.</exception>
		public CodeCave CreateCodeCave(nint address, ReadOnlySpan<byte> payload, int size = 4096)
		{
			var cave = CreateCodeCave(address, size);

			cave.Write(payload);
			return cave;
		}

		// Used for code caves - Page sizes are 4096 bytes (0x1000).
		private nint FindFreeBlockForRegion(nint baseAddress, int size)
		{
			nint minAddress = nint.Subtract(baseAddress, 0x70000000);
			nint maxAddress = nint.Add(baseAddress, 0x70000000);

			nint ret = 0;
			nint tmpAddress;

			GetSystemInfo(out SYSTEM_INFO si);


			if (minAddress > (long)si.maximumApplicationAddress ||
				minAddress < (long)si.minimumApplicationAddress)
				minAddress = si.minimumApplicationAddress;

			if (maxAddress < (long)si.minimumApplicationAddress ||
				maxAddress > (long)si.maximumApplicationAddress)
				maxAddress = si.maximumApplicationAddress;


			nint current = minAddress;
			nint previous;

			while (VirtualQueryEx(procHnd, current, out MEMORY_BASIC_INFORMATION mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != 0)
			{
				if ((long)mbi.BaseAddress > maxAddress)
					return nint.Zero;  // No memory found, let windows handle

				if (mbi.State == MEM_FREE && mbi.RegionSize > size)
				{
					if (mbi.BaseAddress % si.allocationGranularity > 0)
					{
						// The whole size can not be used
						tmpAddress = mbi.BaseAddress;
						int offset = (int)(si.allocationGranularity -
										   (tmpAddress % si.allocationGranularity));

						// Check if there is enough left
						if ((mbi.RegionSize - offset) >= size)
						{
							// yup there is enough
							tmpAddress = nint.Add(tmpAddress, offset);

							if (tmpAddress < baseAddress)
							{
								tmpAddress = nint.Add(tmpAddress, (int)(mbi.RegionSize - offset - size));

								if (tmpAddress > baseAddress)
									tmpAddress = baseAddress;

								// decrease tmpAddress until its alligned properly
								tmpAddress = nint.Subtract(tmpAddress, (int)(tmpAddress % si.allocationGranularity));
							}

							// if the difference is closer then use that
							if (Math.Abs(tmpAddress - baseAddress) < Math.Abs(ret - (long)baseAddress))
								ret = tmpAddress;
						}
					}
					else
					{
						tmpAddress = mbi.BaseAddress;

						if (tmpAddress < baseAddress) // try to get it the cloest possible 
													  // (so to the end of the region - size and
													  // aligned by system allocation granularity)
						{
							tmpAddress = nint.Add(tmpAddress, (int)(mbi.RegionSize - size));

							if (tmpAddress > baseAddress)
								tmpAddress = baseAddress;

							// decrease until aligned properly
							tmpAddress =
								nint.Subtract(tmpAddress, (int)(tmpAddress % si.allocationGranularity));
						}

						if (Math.Abs(tmpAddress - baseAddress) < Math.Abs(ret - baseAddress))
							ret = tmpAddress;
					}
				}

				if (mbi.RegionSize % si.allocationGranularity > 0)
					mbi.RegionSize += si.allocationGranularity - (mbi.RegionSize % si.allocationGranularity);

				previous = current;
				current = new nint((mbi.BaseAddress) + mbi.RegionSize);

				if (current >= maxAddress)
					return ret;

				if (previous >= current)
					return ret; // Overflow
			}

			return ret;
		}

		private nint AllocateCodeCave(nint preferredAddress, int size)
		{
			nint caveAddress = 0;
			nint preferred = preferredAddress;

			for (var i = 0; i < 10 && caveAddress == 0; i++)
			{
				caveAddress = VirtualAllocEx(procHnd, FindFreeBlockForRegion(preferred, size), size,
					MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				if (caveAddress == 0)
					preferred = nint.Add(preferred, 0x10000);
			}

			if (caveAddress == 0)
			{
				caveAddress = VirtualAllocEx(procHnd, (nint)null, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			}

			return caveAddress;
		}

		/// <summary>
		/// Frees up the memory region used by a code cave.
		/// </summary>
		/// <param name="caveAddress">Memory address of the cave to free.</param>
		/// <returns>True if successfully freed.</returns>
		internal bool FreeCave(nint caveAddress)
		{
			var rel = VirtualFreeEx(procHnd, caveAddress, 0, 0x00008000);

			return rel;
		}
	}
}
