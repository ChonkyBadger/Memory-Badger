using System;
using System.Buffers;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using MemoryBadger;
using MemoryBadger.Utilities;

namespace MemoryBadger.Caves
{
	/// <summary>
	/// Class for managing an automated Detour Hook. Inherits from <see cref="CodeCave"/> and will
	/// automatically handle JMP instructions to and from the detour. Does not automatically copy the original
	/// bytes to allow flexibility. this should be done manually if required.
	/// </summary>
	public class Detour : CodeCave
	{
		// OVERRIDES.
		/// <summary>
		/// The first memory address of extra space after the payload.
		/// </summary>
		public override nint ExtraSpaceAddress => Address + Payload.Length + _retJmpLength;

		/// <summary>
		/// The virtual memory address of the original instruction(s) being replaced.
		/// </summary>
		public nint OriginalAddress { get; private set; }
		/// <summary>
		/// Holds a snapshot of the original code instructions before they were overwritten by the detour.
		/// </summary>
		public byte[] OriginalBytes { get; private set; } = [];

		// PRIVATE FIELDS.
		private int _retJmpLength;
		private bool _isHooked;

		internal Detour(Memory memory, nint caveAddress, int caveSize, bool isManaged) 
			: base(memory, caveAddress, caveSize, isManaged)
		{

		}

		/// <summary>
		/// Writes raw bytes safely into this specific cave allocation and creates
		/// a jmp from the original instruction(s) to the cave.
		/// </summary>
		public bool Write(nint originalAddress, int bytesReplaced, ReadOnlySpan<byte> payload)
		{
			if (_isHooked)
				throw new InvalidOperationException("This detour instance is already hooked to the game code.");

			// Write payload, ret JMP and nop padding in extra space.
			if (!Write(payload))
				return false;

			var retJmpAddress = Address + payload.Length;
			var retJmp = Utility.CreateJumpInstruction(retJmpAddress, originalAddress + bytesReplaced);
			if (!_mem.Write(retJmpAddress, retJmp))
				return false;

			// Read and overwrite original bytes.
			var originalBytes = _mem.Read<byte>(originalAddress, bytesReplaced);

			byte[] caveJmp = Utility.CreateJumpInstruction(originalAddress, Address);
			if (_mem.Write(originalAddress, caveJmp))
			{
				OriginalAddress = originalAddress;
				OriginalBytes = originalBytes;
				_retJmpLength = retJmp.Length;

				var trailingBytes = bytesReplaced - caveJmp.Length;
				if (trailingBytes > 0)
				{
					Span<byte> nops = stackalloc byte[trailingBytes];
					nops.Fill(0x90); // 0x90 = NOP
					_mem.Write(OriginalAddress + 5, nops);
				}

				_isHooked = true;
				return true;
			}
			else return false;
		}

		/// <summary>
		/// Overwrites the cave space back to empty instructions (NOPs). Also re-writes the original
		/// instructions and resets <see cref="OriginalAddress"/> and <see cref="OriginalBytes"/>.
		/// </summary>
		public override bool Clear()
		{
			if (OriginalAddress == 0 || OriginalBytes.Length == 0)
				return false;


			if (!_mem.Write(OriginalAddress, OriginalBytes))
				return false;

			OriginalAddress = 0;
			OriginalBytes = [];

			return base.Clear();
		}

		private protected override void OnDispose()
		{
			_mem.Write(OriginalAddress, OriginalBytes);
		}
	}
}
