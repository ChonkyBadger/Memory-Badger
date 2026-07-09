using System;
using System.Buffers;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;

namespace MemoryBadger
{
	/// <summary>
	/// A struct for managing a code cave. Can also be managed as part of a <see cref="SmartCave"/>.
	/// </summary>
	public class Chasm : IDisposable
	{
		/// <summary>
		/// Base memory address of the Chasm.
		/// </summary>
		public nint Address { get; }
		/// <summary>
		/// Size of the memory allocated to the Chasm.
		/// </summary>
		public int Size { get; }
		/// <summary>
		/// Last memory address allocated to the Chasm.
		/// </summary>
		public nint EndAddress { get; }
		/// <summary>
		/// A snapshot copy of the custom assembly payload written into this chasm.
		/// </summary>
		public byte[] Payload { get; }

		/// <summary>
		/// The length of the Chasm payload, not including any allocated extra space.
		/// </summary>
		public int Length { get; }
		/// <summary>
		/// The first memory address after the payload and JMP back to the original code.
		/// </summary>
		public nint ExtraSpaceAddress { get; }
		/// <summary>
		/// Calculates the amount of extra space after the payload before the end of the Chasm.
		/// </summary>
		public int ExtraSpaceLength { get; }

		private readonly bool _standalone;
		private readonly Memory _mem;

		internal Chasm(Memory memoryInstance, nint chasmAddress, int size, byte[] payload, bool selfManaged)
		{
			_mem = memoryInstance;
			Address = chasmAddress;
			Size = size;
			EndAddress = Address + Size;

			Payload = payload;
			Length = Payload.Length + 5;
			ExtraSpaceAddress = Address + Length;
			ExtraSpaceLength = Size - Length;

			_standalone = selfManaged;

			_mem.Write(Address, Payload);

			if (ExtraSpaceLength > 0)
			{
				byte[] rentedBuffer = ArrayPool<byte>.Shared.Rent(ExtraSpaceLength);

				try
				{
					Span<byte> nops = rentedBuffer.AsSpan(0, ExtraSpaceLength);
					nops.Fill(0x90);

					_mem.Write(ExtraSpaceAddress, nops);
				}
				finally
				{
					ArrayPool<byte>.Shared.Return(rentedBuffer);
				}
			}
		}

		/// <summary>
		/// Creates a new <see cref="Chasm"/> at a specified memory address with a specific size. 
		/// Memory allocation should be handled manually, or by a <see cref="Chasm"/>.
		/// Automatically creates a JMP instruction to and from the <see cref="Chasm"/>.
		/// </summary>
		/// <param name="memoryInstance">The instance of <see cref="Memory"/> to be used.</param>
		/// <param name="chasmAddress">The location of the <see cref="Chasm"/> in memory.</param>
		/// <param name="size">Size of memory region allocated to the <see cref="Chasm"/>.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="Chasm"/>.</param>
		internal static Chasm CreateStandalone(Memory memoryInstance, 
			nint chasmAddress, int size, ReadOnlySpan<byte> payload)
		{
			return new Chasm(memoryInstance, chasmAddress, size, payload.ToArray(), true);
		}

		/// <summary>
		/// Creates a new <see cref="Chasm"/> at a specified memory address with a specific size. 
		/// Memory allocation should be handled manually, or by a <see cref="SmartCave"/>.
		/// Automatically creates a JMP instruction to and from the <see cref="Chasm"/>.
		/// </summary>
		/// <param name="memoryInstance">The instance of <see cref="Memory"/> to be used.</param>
		/// <param name="chasmAddress">The location of the <see cref="Chasm"/> in memory.</param>
		/// <param name="extraSpace">Extra space in memory to allocate to the <see cref="SmartChasm"/>.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="Chasm"/>.</param>
		internal static Chasm CreatedManaged(Memory memoryInstance, 
			nint chasmAddress, int extraSpace, ReadOnlySpan<byte> payload)
		{
			var size = payload.Length + extraSpace;

			return new Chasm(memoryInstance, chasmAddress, size, payload.ToArray(), false);
		}

		/// <summary>
		/// Closes the chasm and re-writes the original instructions.
		/// Also unallocates memory where not managed by a <see cref="SmartCave"/>.
		/// </summary>
		public virtual void Close()
		{
			if (_standalone)
				_mem.FreeCave(Address);
		}

		/// <summary>
		/// This is the mandatory IDisposable method. It triggers automatically 
		/// whenever a 'using' block ends.
		/// </summary>
		public void Dispose()
		{
			Close();

			GC.SuppressFinalize(this);
		}
	}

	/// <summary>
	/// Manages an active, intelligent mid-function hook lifecycle inside a code cave.
	/// Automatically handles bidirectional relative jumps and original instruction cloning.
	/// </summary>
	/// <remarks>
	/// This reference type tracks original game states, allowing for automated unhooking. 
	/// It implements <see cref="IDisposable"/> so it can cleanly uninstall its hook when wrapped in a <see langword="using"/> block.
	/// </remarks>
	public class SmartChasm : Chasm
	{
		/// <summary>
		/// The virtual memory address of the original instruction(s) being replaced.
		/// </summary>
		public nint OriginalAddress { get; }
		/// <summary>
		/// A snapshot copy of the original game bytes that were overwritten by this hook. 
		/// </summary>
		public byte[] OriginalBytes { get; }

		private readonly bool _standalone;
		private readonly Memory _mem;

		private SmartChasm(Memory memoryInstance, nint chasmAddress, nint address,
					   int bytesReplaced, int size, byte[] payload, bool selfManaged)
			: base(memoryInstance, chasmAddress, size, payload, selfManaged)
		{
			_mem = memoryInstance;

			OriginalAddress = address;
			OriginalBytes = _mem.Read<byte>(address, bytesReplaced);

			_standalone = selfManaged;

			SetupChasm();
		}

		/// <summary>
		/// Creates a new <see cref="SmartChasm"/> at a specified memory address with a specific size. 
		/// Memory allocation should be handled manually, or by a <see cref="SmartCave"/>.
		/// Automatically creates a JMP instruction to and from the <see cref="SmartChasm"/>.
		/// </summary>
		/// <param name="memoryInstance">The instance of <see cref="Memory"/> to be used.</param>
		/// <param name="chasmAddress">The location of the <see cref="SmartChasm"/> in memory.</param>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <param name="bytesReplaced">The number of bytes being replaced with a JMP to the <see cref="SmartChasm"/>.</param>
		/// <param name="size">Size of memory region allocated to the <see cref="SmartChasm"/>.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="SmartChasm"/>.</param>
		internal static SmartChasm CreateStandalone(Memory memoryInstance, nint chasmAddress, nint address,
			int bytesReplaced, int size, ReadOnlySpan<byte> payload)
		{
			return new SmartChasm(memoryInstance, chasmAddress, address, bytesReplaced, size, payload.ToArray(), true);
		}

		/// <summary>
		/// Creates a new <see cref="SmartChasm"/> at a specified memory address with a specific size. 
		/// Memory allocation should be handled manually, or by a <see cref="SmartCave"/>.
		/// Automatically creates a JMP instruction to and from the <see cref="SmartChasm"/>.
		/// </summary>
		/// <param name="memoryInstance">The instance of <see cref="Memory"/> to be used.</param>
		/// <param name="chasmAddress">The location of the <see cref="SmartChasm"/> in memory.</param>
		/// <param name="address">The target virtual memory address in the external process.</param>
		/// <param name="bytesReplaced">The number of bytes being replaced with a JMP to the <see cref="SmartChasm"/>.</param>
		/// <param name="extraSpace">Extra space in memory to allocate to the <see cref="SmartChasm"/>.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="SmartChasm"/>.</param>
		internal static SmartChasm CreatedManaged(Memory memoryInstance, nint chasmAddress, nint address, 
			int bytesReplaced, int extraSpace, ReadOnlySpan<byte> payload)
		{
			var size = payload.Length + extraSpace + 5;

			return new SmartChasm(memoryInstance, chasmAddress, address, bytesReplaced, size, payload.ToArray(), false);
		}

		private void SetupChasm()
		{
			var currentWritePtr = Address;
			var bytesReplaced = OriginalBytes.Length;

			if (Payload != null)
			{
				_mem.Write(currentWritePtr, Payload);
				currentWritePtr += Payload.Length;
			}

			// JMP offset back to after original instructions.
			nint jmpTo = OriginalAddress + bytesReplaced;
			nint jmpFrom = currentWritePtr + 5;
			int offset = (int)(jmpTo - jmpFrom);

			_mem.Write<byte>(currentWritePtr, 0xE9);
			_mem.Write(currentWritePtr + 1, offset);

			// JMP to Chasm from original instructions.
			jmpTo = Address;
			jmpFrom = OriginalAddress + 5;
			offset = (int)(jmpTo - jmpFrom);

			_mem.Write<byte>(OriginalAddress, 0xE9);
			_mem.Write(OriginalAddress + 1, offset);

			// NOP trailing bytes.
			var trailingBytes = bytesReplaced - 5;
			if (trailingBytes > 0)
			{
				Span<byte> nops = stackalloc byte[trailingBytes];
				nops.Fill(0x90); // 0x90 = NOP
				_mem.Write(OriginalAddress + 5, nops);
			}
		}

		/// <summary>
		/// Closes the chasm and re-writes the original instructions.
		/// Also unallocates memory where not managed by a <see cref="SmartCave"/>.
		/// </summary>
		public override void Close()
		{
			_mem.Write(OriginalAddress, OriginalBytes);

			base.Close();
		}
	}

	/// <summary>
	/// A smart code cave class for managing smaller "chasms" within one code cave, 
	/// preventing the need to create many codes caves just for one mod.
	/// </summary>
	public class SmartCave
	{
		/// <summary>
		/// Base memory address of the Cave.
		/// </summary>
		public nint Address { get; }
		/// <summary>
		/// Size of the memory allocated to the Cave.
		/// </summary>
		public int Size { get; }
		/// <summary>
		/// List of managed <see cref="Chasm"/>. within the SmartCave.
		/// </summary>
		public List<Chasm> Chasms { get; } = [];
		/// <summary>
		/// List of managed <see cref="SmartChasm"/>. within the SmartCave.
		/// </summary>
		public List<SmartChasm> SmartChasms { get; } = [];

		// Private fields.
		private readonly nint _endAddress;
		private nint _allocatedBytes = 0;
		private readonly Memory _mem;

		private readonly int _dataAlignment;
		private readonly int _codeAlignment;


		internal SmartCave(Memory memoryInstace, nint address, int size)
		{
			_mem = memoryInstace;
			Address = address;
			Size = size;
			_endAddress = Address + Size;

			_dataAlignment = Unsafe.SizeOf<nint>();
			_codeAlignment = _dataAlignment * 2;
		}


		private nint? GetChasmAddress(int size)
		{
			if (size <= 0)
				return null;

			var chasmAddress = Address + _allocatedBytes;
			var endAddress = chasmAddress + size;

			if (endAddress > _endAddress)
				return null;

			return chasmAddress;
		}

		/// <summary>
		/// Creates a new <see cref="Chasm"/>, managed by the <see cref="Chasm"/>
		/// <param name="extraSpace">Extra space in memory to allocate to the <see cref="Chasm"/>.
		/// Extra space may be automatically added to ensure proper alignment for instructions.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="Chasm"/>.</param>
		/// </summary>
		public Chasm? CreateChasm(int extraSpace, ReadOnlySpan<byte> payload)
		{
			var size = payload.Length + extraSpace + 5;
			var chasmAddress = GetChasmAddress(size);

			if (chasmAddress == null)
				return null;

			int alignedSize = (size + (_codeAlignment - 1)) & ~(_codeAlignment - 1);
			int difference = alignedSize - size;
			var chasm = Chasm.CreatedManaged(_mem, chasmAddress.Value, extraSpace + difference, payload);
			Chasms.Add(chasm);

			_allocatedBytes += alignedSize;

			return chasm;
		}

		/// <summary>
		/// Creates a new <see cref="SmartChasm"/>, managed by the <see cref="SmartCave"/>
		/// <param name="address">The preferred baseline address to start searching from.</param>
		/// <param name="bytesReplaced">The number of bytes being replaced with a JMP to the <see cref="SmartChasm"/>.</param>
		/// <param name="extraSpace">Extra space in memory to allocate to the <see cref="SmartChasm"/>.
		/// Extra space may be automatically added to ensure proper alignment for instructions.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="SmartChasm"/>.</param>
		/// </summary>
		public SmartChasm? CreateSmartChasm(nint address, int bytesReplaced, int extraSpace, ReadOnlySpan<byte> payload)
		{
			var size = payload.Length + extraSpace + 5;
			var chasmAddress = GetChasmAddress(size);

			if (chasmAddress == null)
				return null;

			int alignedSize = (size + (_codeAlignment - 1)) & ~(_codeAlignment - 1);
			int difference = alignedSize - size;
			var chasm = SmartChasm.CreatedManaged(_mem, chasmAddress.Value, 
				address, bytesReplaced, extraSpace + difference, payload);
			SmartChasms.Add(chasm);

			_allocatedBytes += alignedSize;

			return chasm;
		}

		/// <summary>
		/// Closes all instances of <see cref="SmartChasms"/> in the <see cref="SmartCave"/>.
		/// </summary>
		public void CloseChasms()
		{
			foreach (SmartChasm chasm in SmartChasms)
			{
				chasm.Close();
			}
		}

		/// <summary>
		/// Closes the <see cref="SmartCave"/> along with all of its SmartChasms. Chasms should be manually reset before hand.
		/// </summary>
		/// <returns></returns>
		public bool CloseCave()
		{
			CloseChasms();

			return _mem.FreeCave(Address);
		}
	}
}
