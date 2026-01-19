using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections;

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
			ushort reserved;
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

		[DllImport("kernel32.dll")]
		internal static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

		[DllImport("kernel32.dll")]
		internal static extern bool CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll")] // Read Memory
		internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
			[Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

		[DllImport("kernel32.dll")] // Read Memory
		internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
			[Out] byte[] lpBuffer, int dwSize, int lpNumberOfBytesRead);

		[DllImport("kernel32.dll")]
		internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
			byte[] lpBuffer, int size, int lpNumberOfBytesWritten);

		[DllImport("kernel32.dll")] // Get info on memory pages
		internal static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
			out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

		private bool VirtualQueryExB(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer)
		{
			MEMORY_BASIC_INFORMATION tmp64 = new MEMORY_BASIC_INFORMATION();
			bool retVal = VirtualQueryEx(hProcess, lpAddress, out tmp64, Marshal.SizeOf(tmp64));

			lpBuffer.BaseAddress = tmp64.BaseAddress;
			lpBuffer.AllocationBase = tmp64.AllocationBase;
			lpBuffer.AllocationProtect = tmp64.AllocationProtect;
			lpBuffer.RegionSize = tmp64.RegionSize;
			lpBuffer.State = tmp64.State;
			lpBuffer.Protect = tmp64.Protect;
			lpBuffer.Type = tmp64.Type;

			return retVal;

		}

		[DllImport("kernel32.dll")]
		internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddres,
			int dwSize, uint flAllocationType, uint flProtect);

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
		internal static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
			int dwSize, int dwFreeType);

		[DllImport("kernel32.dll")]
		internal static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

		// Rights
		private const uint PROCESS_ALL_ACCESS = 0x1fffff;
		// Constants for Memory Regions
		private const uint MEM_COMMIT = 0x1000;
		private const uint MEM_FREE = 0x10000;
		private const uint MEM_RESERVE = 0x2000;
		private const uint PAGE_READONLY = 0x02;
		private const uint PAGE_READWRITE = 0x04;
		private const uint PAGE_EXECUTE_READWRITE = 0x40;

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
		public byte[] ConvertStringToBytes(string byteString)
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
		/// <param name="offsetString">Integers up to 64 bits in a string format ("FF CDE</param>
		/// <returns></returns>
		public long[] ConvertHexStringToInt64Array(string offsetString)
		{
			string[] split = offsetString.Split(" "); // FF FF FF -> FF,FF,FF.
			long[] offsets = new long[split.Length];

			for (int i = 0; i < split.Length; i++)
			{
				offsets[i] = Convert.ToInt64(split[i], 16);
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
		/// Reads the final memory address after pointer offsets have been applied.
		/// </summary>
		/// <param name="address">Initial memory address of the pointer.</param>
		/// <param name="offsets">String of offsets to be applied to the pointer (e.g. "A4 C3D 1F").</param>
		/// <returns></returns>
		public nint GetCode(string address, string offsets) => 
			GetCode(address, ConvertHexStringToInt64Array(offsets));

		/// <summary>
		/// Reads the final memory address after pointer offsets have been applied.
		/// </summary>
		/// <param name="address">Initial memory address of the pointer in string format. Example format:
		/// "gamedll_ph_x64_rwdi.dll+FB3CB3" - A + can optionally be used to separate strings where
		/// one part of it is the module name and the other is an offset.</param>
		/// <param name="offsets">String of offsets to be applied to the pointer (e.g. "A4 C3D 1F").</param>
		/// <returns></returns>
		public nint GetCode(nint address, string offsets) => 
			GetCode(address, ConvertHexStringToInt64Array(offsets));

		/// <summary>
		/// Reads the final memory address after pointer offsets have been applied.
		/// </summary>
		/// <param name="address">Initial memory address of the pointer in string format. Example format:
		/// "gamedll_ph_x64_rwdi.dll+FB3CB3" - A + can optionally be used to separate strings where
		/// one part of it is the module name and the other is an offset.</param>
		/// <param name="offsets">Array of offsets to be applied to the pointer.</param>
		/// <returns></returns>
		public nint GetCode(string address, long[] offsets)
		{
			if (string.IsNullOrEmpty(address))
			{
				return 0;
			}

			// Remove Spaces
			address.Replace(" ", string.Empty);

			nint code = 0;
			address = address.ToLower();

			if (address.Contains('+'))
			{
				string[] newCode = address.Split('+');
				nint offset = nint.Parse(newCode[1], System.Globalization.NumberStyles.AllowHexSpecifier);
				code = GetModuleAddressByName(newCode[0]) + offset;
			}
			else code = GetModuleAddressByName(address);

			return GetCode(code, offsets);
		}

		/// <summary>
		/// Reads the final address after pointer offsets have been applied.
		/// </summary>
		/// <param name="address">Initial address of the pointer.</param>
		/// <param name="offsets">Array of offsets to be applied to the pointer.</param>
		/// <returns></returns>
		public nint GetCode(nint address, long[] offsets)
		{
			byte[] memoryAddress = new byte[nint.Size];
			ReadProcessMemory(procHnd, address, memoryAddress, nint.Size, 0);
			address = (nint)BitConverter.ToInt64(memoryAddress);

			if (offsets.Length > 0)
			{
				var val = address;
				foreach (var o in offsets)
				{
					address = val + (nint)o;
					ReadProcessMemory(procHnd, address, memoryAddress, nint.Size, 0);
					val = (nint)BitConverter.ToInt64(memoryAddress, 0);
				}
			}
			return address;
		}
		#endregion

		#region Internal Methods
		// Used for code caves - Page sizes are 4096 bytes (0x1000).
		internal nint FindFreeBlockForRegion(nint baseAddress, int size)
		{
			nint minAddress = nint.Subtract(baseAddress, 0x70000000);
			nint maxAddress = nint.Add(baseAddress, 0x70000000);

			nint ret = 0;
			nint tmpAddress = 0;

			GetSystemInfo(out SYSTEM_INFO si);


			if (minAddress > (long)si.maximumApplicationAddress ||
				minAddress < (long)si.minimumApplicationAddress)
				minAddress = si.minimumApplicationAddress;

			if (maxAddress < (long)si.minimumApplicationAddress ||
				maxAddress > (long)si.maximumApplicationAddress)
				maxAddress = si.maximumApplicationAddress;


			MEMORY_BASIC_INFORMATION mbi;

			nint current = minAddress;
			nint previous = current;

			while (VirtualQueryExB(procHnd, current, out mbi) != false)
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
		#endregion
	}
}
