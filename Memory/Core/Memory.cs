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
			nint lpNumberOfBytesRead);

		[LibraryImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool ReadProcessMemory(
			nint hProcess, 
			nint lpBaseAddress,
			Span<byte> lpBuffer, 
			int dwSize, 
			out nint lpNumberOfBytesRead);

		[LibraryImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool WriteProcessMemory(
			nint hProcess,
			nint lpBaseAddress,
			ReadOnlySpan<byte> lpBuffer, 
			int size, 
			nint lpNumberOfBytesWritten);

		[LibraryImport("kernel32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static partial bool WriteProcessMemory(
			nint hProcess,
			nint lpBaseAddress,
			ReadOnlySpan<byte> lpBuffer,
			int size,
			out nint lpNumberOfBytesWritten);

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
		/// Gets a specific module by name.
		/// </summary>
		/// <param name="name">Module name (e.g. "gamedll_x64_rwdi.dll").</param>
		/// <returns>Base memory address of specified module.</returns>
		public ProcessModule? GetModuleByName(string name)
		{
			var module = proc.Modules.Cast<ProcessModule>().SingleOrDefault(
				m => string.Equals(m.ModuleName, name, StringComparison.OrdinalIgnoreCase));

			if (module != null)
				return module;
			else return default;
		}

		/// <summary>
		/// Reads the final address of a multi-level pointer.
		/// Example usage: GetAddress(baseAddress + 0x26A, [0x40, 0x08, 0x28]).
		/// </summary>
		/// <param name="baseAddress">Initial address of the pointer.</param>
		/// <param name="offsets">Array of offsets to be applied to the pointer.</param>
		/// <returns></returns>
		public nint GetAddress(nint baseAddress, ReadOnlySpan<int> offsets)
		{
			// High-performance boundary check: spans utilize internal compiler length optimizations
			if (offsets.Length == 0)
				return baseAddress;

			nint currentAddress = Read<nint>(baseAddress);

			if (currentAddress == 0) 
				return 0;

			for (int i = 0; i < offsets.Length; i++)
			{
				nint targetAddress = currentAddress + offsets[i];

				// If we are at the very last offset, return the destination address
				if (i == offsets.Length - 1)
				{
					return targetAddress;
				}

				// Read the next nested pointer value
				currentAddress = Read<nint>(targetAddress);

				// Safe Guard: Stop instantly if any pointer in the chain resolves to null
				if (currentAddress == 0)
				{
					return 0;
				}
			}

			return 0;
		}
	}
}