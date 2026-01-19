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

namespace MemoryBadger
{
	public partial class Memory
	{
		/// <summary>
		/// Reads bytes from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from..</param>
		/// <param name="length">Number of bytes to read.</param>
		/// <returns>Bytes at memory address.</returns>
		public byte[] ReadBytes(nint address, int length)
		{
			if (address < 0x10000)
				return [];

			byte[] bytes = new byte[length];
			ReadProcessMemory(procHnd, address, bytes, length, 0);
			return bytes;
		}
		/// <summary>
		/// Reads bytes from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="length">Number of bytes to read.</param>
		/// <returns>Bytes at memory address.</returns>
		public byte[] ReadBytes(nint address, long[] offsets, int length) => ReadBytes(GetCode(address, offsets), length);

		// Conversion methods for ReadBytes();
		/// <summary>
		/// Reads a 32-bit integer from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <returns>Integer value at memory address.</returns>
		public int ReadInt(nint address) => BitConverter.ToInt32(ReadBytes(address, 4));
		/// <summary>
		/// Reads a 32-bit integer value from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <returns>Integer value at memory address.</returns>
		public int ReadInt(nint address, long[] offsets) => ReadInt(GetCode(address, offsets));

		/// <summary>
		/// Reads a 64-bit integer value from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <returns>64-bit integer value at memory address.</returns>
		public long ReadLong(nint address) => BitConverter.ToInt64(ReadBytes(address, 8));
		/// <summary>
		/// Reads a 64-bit integer value from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <returns>64-bit integer value at memory address.</returns>
		public long ReadLong(nint address, long[] offsets) => ReadLong(GetCode(address, offsets));

		/// <summary>
		/// Reads a float value from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <param name="round">Whether to round the float to a specified number of places.</param>
		/// <param name="digits">Number of decimal places to round to (if round is true).</param>
		/// <returns>Float value at memory address.</returns>
		public float ReadFloat(nint address, bool round = true, int digits = 2)
		{
			var bytes = ReadBytes(address, 4);
			if (bytes.Length > 0)
			{
				
				var value = BitConverter.ToSingle(bytes, 0);
				if (round)
					return (float)Math.Round(value, digits);
				else return value;
			}
			else return 0;
		}
		/// <summary>
		/// Reads a float value from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address.</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="round">Whether to round the float to a specified number of places.</param>
		/// <param name="digits">Number of decimal places to round to (if round is true).</param>
		/// <returns>float value at memory address.</returns>
		public float ReadFloat(nint address, long[] offsets, bool round = true, int digits = 2) => ReadFloat(GetCode(address, offsets), round, digits);

		/// <summary>
		/// Reads a string from a specific memory address.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <param name="length">Length of the string in bytes.</param>
		/// <param name="stringEncoding">Encoding type to use for the string. 
		/// If left as null, it will be set to UTF8 by default.</param>
		/// <param name="zeroTerminated">Whether or not it should terminate upon reading
		/// a zero (0x00). This usually indicates the end of a string.</param>
		/// <returns>String value read from memory address.</returns>
		public string ReadString(nint address, int length, Encoding? stringEncoding = null, bool zeroTerminated = true)
		{
			var bytes = ReadBytes(address, length);

			if (stringEncoding == null)
			{
				stringEncoding = Encoding.UTF8;
			}

			if (bytes.Length > 0)
			{
				return (zeroTerminated) ? stringEncoding.GetString(bytes).Split('\0')[0] : stringEncoding.GetString(bytes);
			}
			else return string.Empty;
		}
		/// <summary>
		/// Reads a string from a pointer address.
		/// </summary>
		/// <param name="address">Base pointer address..</param>
		/// <param name="offsets">Offsets to add to the base pointer address.</param>
		/// <param name="length">Length of the string in bytes.</param>
		/// <param name="stringEncoding">Encoding type to use for the string. 
		/// If left as null, it will be set to UTF8 by default.</param>
		/// <param name="zeroTerminated">Whether or not it should terminate upon reading
		/// a zero (0x00). This usually indicates the end of a string.</param>
		/// <returns>String value read memory address.</returns>
		public string ReadString(nint address, long[] offsets, int length, Encoding? stringEncoding = null, bool zeroTerminated = true) => ReadString(GetCode(address, offsets), length, stringEncoding, zeroTerminated);

		/// <summary>
		/// Reads bytes from a specific memory address and returns them as a BitArray.
		/// </summary>
		/// <param name="address">Memory address to read from.</param>
		/// <param name="byteLength">Number of bytes to read.</param>
		/// <returns>BitArray from the bytes read.</returns>
		public BitArray ReadBits(nint address, int byteLength) => new BitArray(ReadBytes(address, byteLength));

		// AOB-Pattern scanning.
		/// <summary>
		/// Scans for an array of bytes, returning a list of results. 
		/// To avoid bad results, try to make the array of bytes as unique as possible. 
		/// </summary>
		/// <param name="byteString">Bytes to scan for in string format. (e.g. "A1 C3 08")
		/// 0 can be used to indicate a "wildcard" which can be any value.</param>
		/// <param name="address">Base address of memory module to start scan from.</param>
		/// <returns>List contining address found matching provided byte signature.
		/// If the scan was good, it is usually the first address.</returns>
		public List<nint> ScanMemory(string byteString, nint address = 0) => ScanMemory(ConvertStringToBytes(byteString), address);

		// AOB-Pattern scanning.
		/// <summary>
		/// Scans for an array of bytes, returning a list of results. 
		/// To avoid bad results, try to make the array of bytes as unique as possible. 
		/// </summary>
		/// <param name="bytes">Bytes to scan for. 0 can be used to indicate a "wildcard" which can be any value.
		/// 0 can be used to indicate a "wildcard" which can be any value.</param>
		/// <param name="address">Base address of memory module to start scan from.</param>
		/// <returns>List contining address found matching provided byte signature.
		/// If the scan was good, it is usually the first address.</returns>
		public List<nint> ScanMemory(byte[] bytes, nint address = 0)
		{
			List<nint> results = new();

			int bytesRead = 0;

			// Iterate through all memory regions for signature.
			while (VirtualQueryEx(procHnd, address, out MEMORY_BASIC_INFORMATION
				mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))))
			{
				if (mbi.State == MEM_COMMIT && (mbi.Protect != PAGE_READWRITE || mbi.Protect != PAGE_READONLY))
				{
					byte[] buffer = new byte[(int)mbi.RegionSize];
					if (ReadProcessMemory(procHnd, mbi.BaseAddress, buffer, buffer.Length, out bytesRead))
					{
						// Only read inside boundaries
						for (int i = 0; i < bytesRead - bytes.Length; i++)
						{
							bool match = true;
							for (int j = 0; j < bytes.Length; j++)
							{
								// Check bytes compared to our signature and ignore wildcards (0)
								if (bytes[j] != 0 && buffer[i + j] != bytes[j])
								{
									match = false;
									break;
								}
							}
							if (match)
							{
								results.Add(mbi.BaseAddress + i); // Add match to results list.
							}
						}
					}
				}
				address = new nint(address + mbi.RegionSize);
			}
			return results;
		}
	}
}
