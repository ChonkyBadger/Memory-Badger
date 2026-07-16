using System.Collections;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;

namespace MemoryBadger.Utilities
{
	/// <summary>
	/// Holds all memory related methods.
	/// </summary>
	public class Utility
	{
		/// <summary>
		/// Converts a string to a byte[].
		/// </summary>
		/// <param name="byteString">Hexadecimal bytes in string form ("48 8B 33...").</param>
		/// <param name="destination">Destination <see cref="Span{T}"/> to write bytes to.</param>
		/// <returns>Number of bytes written to <paramref name="destination"/></returns>
		public static int ParseHexStringAsBytes(string byteString, Span<byte> destination)
		{
			if (string.IsNullOrWhiteSpace(byteString) || destination.IsEmpty)
				return 0;

			int index = 0;
			int len = byteString.Length;
			int pos = 0;

			while (pos < len)
			{
				// Skip any spaces
				while (pos < len && byteString[pos] == ' ') pos++;
				if (pos >= len) break;
				if (index >= destination.Length) break;

				// Find the end of the current hex token
				int nextSpace = byteString.IndexOf(' ', pos);
				int tokenEnd = nextSpace == -1 ? len : nextSpace;
				int tokenLen = tokenEnd - pos;

				// Convert and write directly into the existing destination span
				destination[index++] = Convert.ToByte(byteString.Substring(pos, tokenLen), 16);

				pos = tokenEnd;
			}

			return index; // Returns the exact number of bytes written
		}

		/// <summary>
		/// Converts a space-separated hex string with wildcards into a span of nullable bytes.
		/// </summary>
		/// <param name="byteString">Hexadecimal bytes and wildcards in string form ("48 8B ?? ?? 33...").</param>
		/// <param name="destination">Destination <see cref="Span{T}"/> to write nullable bytes to.</param>
		/// <returns>Number of bytes written to <paramref name="destination"/>.</returns>
		public static int ParseHexStringAsNullableBytes(ReadOnlySpan<char> byteString, Span<byte?> destination)
		{
			if (byteString.IsEmpty || destination.IsEmpty)
				return 0;

			int index = 0;
			int len = byteString.Length;
			int pos = 0;

			while (pos < len)
			{
				// Skip spaces
				while (pos < len && byteString[pos] == ' ') pos++;
				if (pos >= len || index >= destination.Length) break;

				// Slice to find the token length without allocating memory
				int nextSpace = byteString[pos..].IndexOf(' ');
				int tokenLen = nextSpace == -1 ? len - pos : nextSpace;

				if (tokenLen == 0) break;

				ReadOnlySpan<char> token = byteString.Slice(pos, tokenLen);

				// Check for wildcards
				if (token is "?" or "??")
				{
					destination[index++] = null;
				}
				else
				{
					// Fix: Natively parse the hex span safely with zero allocations
					if (byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte parsedByte))
					{
						destination[index++] = parsedByte;
					}
				}

				pos += tokenLen;
			}

			return index;
		}

		/// <summary>
		/// Converts a string to a byte[].
		/// </summary>
		/// <param name="byteString">Hexadecimal bytes in string form ("48 8B 33...").</param>
		/// <returns>byte[] version of the provided string.</returns>
		public static byte[] ParseHexStringAsBytes(string byteString)
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
		public static int[] ParseHexStringAsIntArray(string offsetString)
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
		/// Creates a JMP instruction based on a to and from address.
		/// </summary>
		/// <param name="fromAddress">Address to create JMP from.</param>
		/// <param name="toAddress">Address to create JMP to.</param>
		/// <param name="is64Bit">True for 64-bit absolute jumps; false for 32-bit relative jumps.</param>
		/// <returns></returns>
		public static byte[] CreateJumpInstruction(nint fromAddress, nint toAddress, bool is64Bit = false)
		{
			if (!is64Bit)
			{
				// 32-bit Relative Jump: E9 [4-byte offset]
				// Explicitly calculate relative offset from the END of this 5-byte instruction
				int relativeOffset = (int)(toAddress - (fromAddress + 5));

				byte[] jmp = new byte[5];
				jmp[0] = 0xE9;

				// Use MemoryMarshal to write directly into the span of the array without BitConverter allocations
				MemoryMarshal.Write(jmp.AsSpan(1), in relativeOffset);
				return jmp;
			}
			else
			{
				// Clean x64 Absolute RIP-Relative Jump: FF 25 [00 00 00 00] [8-byte target address]
				byte[] jmp = new byte[14];
				jmp[0] = 0xFF;
				jmp[1] = 0x25;
				// bytes 2 to 5 remain 0x00 for [RIP+0] displacement

				// Convert nint directly to long to guarantee an 8-byte buffer write on x64
				long absoluteAddress = toAddress;
				MemoryMarshal.Write(jmp.AsSpan(6), in absoluteAddress);
				return jmp;
			}
		}
	}
}
