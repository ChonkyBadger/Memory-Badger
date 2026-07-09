using System.Collections;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Drawing;
using System.Net;
using System.Runtime.InteropServices;

namespace MemoryBadger
{
	/// <summary>
	/// Holds all memory related methods.
	/// </summary>
	public partial class Memory
	{
		internal struct MEMORY_BASIC_INFORMATION
		{
			public nint BaseAddress;
			public nint AllocationBase;
			public uint AllocationProtect;
			public long RegionSize;
			public uint State;
			public uint Protect;
			public uint Type;
		}

		internal struct SYSTEM_INFO
		{
			public ushort processorArchitecture;
			public readonly ushort reserved;
			public uint pageSize;
			public nint minimumApplicationAddress;
			public nint maximumApplicationAddress;
			public nint activeProcessorMask;
			public uint numberOfProcessors;
			public uint processorType;
			public uint allocationGranularity;
			public ushort processorLevel;
			public ushort processorRevision;
		}

		private Process proc = new();
		internal nint procHnd = 0;

		[LibraryImport("kernel32.dll")]
		internal static partial nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

		[LibraryImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool CloseHandle(nint hObject);

		[LibraryImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool ReadProcessMemory(
			nint hProcess, 
			nint lpBaseAddress,
			Span<byte> lpBuffer, 
			int dwSize, 
			int lpNumberOfBytesRead);

		[LibraryImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool ReadProcessMemory(
			nint hProcess, 
			nint lpBaseAddress,
			Span<byte> lpBuffer, 
			int dwSize, 
			out int lpNumberOfBytesRead);

		[LibraryImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool WriteProcessMemory(
			nint hProcess,
			nint lpBaseAddress,
			ReadOnlySpan<byte> lpBuffer, 
			int size, 
			int lpNumberOfBytesWritten);

		[LibraryImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool WriteProcessMemory(
			nint hProcess,
			nint lpBaseAddress,
			ReadOnlySpan<byte> lpBuffer,
			int size,
			out int lpNumberOfBytesWritten);

		[LibraryImport("kernel32.dll", EntryPoint = "VirtualQueryEx", SetLastError = true)]
		internal static partial int VirtualQueryEx(
		nint hProcess,
		nint lpAddress,
		out MEMORY_BASIC_INFORMATION lpBuffer,
		int dwLength);

		[LibraryImport("kernel32.dll")]
		internal static partial IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddres,
			int dwSize, uint flAllocationType, uint flProtect);

		[LibraryImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
			int dwSize, int dwFreeType);

		[LibraryImport("kernel32.dll")]
		internal static partial void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

		// Rights
		private const uint PROCESS_ALL_ACCESS = 0x1fffff;
		// Constants for Memory Regions
		private const uint MEM_COMMIT = 0x1000;
		private const uint MEM_FREE = 0x10000;
		private const uint MEM_RESERVE = 0x2000;
		private const uint PAGE_READONLY = 0x02;
		private const uint PAGE_READWRITE = 0x04;
		private const uint PAGE_EXECUTE_READWRITE = 0x40;
		//private const uint WRITABLE_PROTECT = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE;

		#region Public Methods
		/// <summary>
		/// Opens a process.
		/// </summary>
		/// <param name="processName">Name of the process to open.</param>
		/// <returns>True if successful.</returns>
		public bool Attach(string processName)
		{
			if (procHnd != 0)
			{
				_ = CloseHandle(procHnd);
			}
			
			var procs = Process.GetProcessesByName(processName);

			if (procs.Length == 0)
				return false;
			else
			{
				proc = procs[0];
			}

			if (proc != null)
			{
				procHnd = OpenProcess(PROCESS_ALL_ACCESS, false, proc.Id);
				if (procHnd != 0)
				{
					return true;
				}
				else return false;
			}
			else return false;
		}

		/// <summary>
		/// Closes the currently opened process.
		/// </summary>
		/// <returns>True if successful.</returns>
		public bool Close()
		{
			if (procHnd != 0)
			{
				var closed = CloseHandle(procHnd);

				if (closed)
					procHnd = 0;

				return closed;
			}
			else return true;
		}

		/// <summary>
		/// Converts a string to a byte[].
		/// </summary>
		/// <param name="byteString">Hexadecimal bytes in string form ("48 8B 33...").</param>
		/// <returns>byte[] version of the provided string.</returns>
		public static byte[] ConvertStringToBytes(string byteString)
		{
			string[] splitBytes = byteString.Split(" "); // FF FF FF -> FF,FF,FF.
			byte[] bytes = new byte[splitBytes.Length];

			for(int i = 0; i < splitBytes.Length; i++)
			{
				bytes[i] = Convert.ToByte(splitBytes[i], 16);
			}

			return bytes;
		}

		/// <summary>
		/// Converts a hexadecimal string to a 64-bit integer array.
		/// </summary>
		/// <param name="offsetString">Integers up to 32 bits in a string format ("FF CDE")</param>
		/// <returns>Returns each integer in an array of <see cref="int"/></returns>
		public static int[] ConvertHexStringToIntArray(string offsetString)
		{
			string[] split = offsetString.Split(" "); // FF FF FF -> FF,FF,FF.
			int[] offsets = new int[split.Length];

			for (int i = 0; i < split.Length; i++)
			{
				offsets[i] = Convert.ToInt32(split[i], 16);
			}
			return offsets;
		}

		/// <summary>
		/// Gets the base memory address of a specific module by name.
		/// </summary>
		/// <param name="name">Module name (e.g. "gamedll_x64_rwdi.dll").</param>
		/// <returns>Base memory address of specified module.</returns>
		public nint GetModuleAddressByName(string name)
		{
			var module = proc.Modules.Cast<ProcessModule>().SingleOrDefault(
				m => string.Equals(m.ModuleName, name, StringComparison.OrdinalIgnoreCase));

			if (module != null)
				return module.BaseAddress;
			else return 0;
		}

		/// <summary>
		/// Reads the final address of a multi-level pointer.
		/// Example usage: GetAddress(baseAddress + 0x26A, [0x40, 0x08, 0x28]).
		/// </summary>
		/// <param name="baseAddress">Initial address of the pointer.</param>
		/// <param name="offsets">Array of offsets to be applied to the pointer.</param>
		/// <returns></returns>
		public nint GetAddress(nint baseAddress, int[] offsets)
		{
			if (offsets == null || offsets.Length == 0)
				return baseAddress;

			nint address = Read<nint>(baseAddress);

			// Read all but final offset.
			for (int i = 0; i < offsets.Length - 1; i++)
				address = Read<nint>(address + offsets[i]);

			// Add final offset.
			return address + offsets[^1];
		}
		#endregion

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
