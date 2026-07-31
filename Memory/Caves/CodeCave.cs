using System;
using System.Buffers;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using MemoryBadger;

namespace MemoryBadger.Caves
{
	/// <summary>
	/// Class for managing a CodeCave.
	/// </summary>
	public class CodeCave : IDisposable
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
		public byte[] Payload { get; private set; } = [];
		/// <summary>
		/// The first memory address of extra space after the payload.
		/// </summary>
		public virtual nint ExtraSpaceAddress => Address + Payload.Length;
		/// <summary>
		/// Calculates the amount of extra space after the payload before the end of the Chasm.
		/// </summary>
		public int ExtraSpaceLength => (int)(Size - ExtraSpaceAddress);

		/// <summary>
		/// Whether or not the <see cref="CodeCave"/> has been disposed of (<see cref="Dispose"/>)
		/// </summary>
		protected bool IsDisposed;

		// PRIVATE FIELDS.
		private protected readonly Memory _mem;
		private protected readonly bool _isManaged;

		// Internal Constructor
		internal CodeCave(Memory memory, nint caveAddress, int caveSize, bool isManaged)
		{
			_mem = memory ?? throw new ArgumentNullException(nameof(memory));
			Address = caveAddress;
			Size = caveSize;
			EndAddress = Address + Size;
			_isManaged = isManaged;
		}

		/// <summary>
		/// Writes raw bytes safely into this specific cave allocation.
		/// </summary>
		public virtual bool Write(ReadOnlySpan<byte> payload)
		{
			ObjectDisposedException.ThrowIf(IsDisposed, this);

			if (payload.Length > Size)
				return false;

			if (!_mem.Write(Address, payload))
				return false;

			Payload = payload.ToArray();
			if (ExtraSpaceLength > 0)
				WriteNop(ExtraSpaceAddress, ExtraSpaceLength);
			return true;
		}

		/// <summary>
		/// Overwrites the cave space back to empty instructions (NOPs).
		/// </summary>
		public virtual bool Clear()
		{
			ObjectDisposedException.ThrowIf(IsDisposed, this);

			if (Size <= 0) return true;

			// Use optimization to clear the entire allocated size
			if (!WriteNop(Address, Size))
				return false;

			Payload = [];
			return true;
		}

		private protected bool WriteNop(nint address, int length)
		{
			byte[] rentedBuffer = ArrayPool<byte>.Shared.Rent(length);
			try
			{
				Span<byte> nops = rentedBuffer.AsSpan(0, length);
				nops.Fill(0x90);

				if (!_mem.Write(address, nops))
					return false;
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(rentedBuffer);
			}

			return true;
		}

		/// <summary>
		/// This is the mandatory IDisposable method. It triggers automatically 
		/// whenever a 'using' block ends. Frees the code cave where not managed.
		/// </summary>
		public virtual void Dispose()
		{
			if (IsDisposed) return;

			OnDispose();

			if (!_isManaged)
				_mem.FreeCave(Address);
			Clear();

			GC.SuppressFinalize(this);
		}

		private protected virtual void OnDispose()
		{

		}
	}
}
