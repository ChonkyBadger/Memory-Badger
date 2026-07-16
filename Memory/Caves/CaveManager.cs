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
	/// A smart code cave class for managing smaller "CodeCaves" within one code cave, 
	/// preventing the need to create many codes caves just for one mod.
	/// </summary>
	public class CaveManager : IDisposable
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
		/// List of managed <see cref="CodeCave"/>. within the CaveManager.
		/// </summary>
		public List<CodeCave> CodeCaves { get; } = [];
		/// <summary>
		/// List of managed <see cref="Detour"/>. within the CaveManager.
		/// </summary>
		public List<Detour> Detours { get; } = [];

		// Private fields.
		private readonly nint _endAddress;
		private nint _allocatedBytes = 0;
		private readonly Memory _mem;

		private readonly int _dataAlignment;
		private readonly int _codeAlignment;
		private bool _isDisposed;


		internal CaveManager(Memory memoryInstace, nint address, int size)
		{
			_mem = memoryInstace;
			Address = address;
			Size = size;
			_endAddress = Address + Size;

			_dataAlignment = Unsafe.SizeOf<nint>();
			_codeAlignment = _dataAlignment * 2;
		}


		private nint? GetCodeCaveAddress(int size)
		{
			if (size <= 0)
				return null;

			var CodeCaveAddress = Address + _allocatedBytes;
			var endAddress = CodeCaveAddress + size;

			if (endAddress > _endAddress)
				return null;

			return CodeCaveAddress;
		}

		/// <summary>
		/// Creates a new <see cref="CodeCave"/>, managed by the <see cref="CodeCave"/> and automatically
		/// writes the CodeCave payload.
		/// <param name="extraSpace">Extra space in memory to allocate to the <see cref="CodeCave"/>.
		/// Extra space may be automatically added to ensure proper alignment for instructions.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="CodeCave"/>.</param>
		/// </summary>
		public CodeCave? CreateCodeCave(int extraSpace, ReadOnlySpan<byte> payload)
		{
			var size = payload.Length + extraSpace;
			var CodeCaveAddress = GetCodeCaveAddress(size);

			if (CodeCaveAddress == null)
				return null;

			int alignedSize = (size + (_codeAlignment - 1)) & ~(_codeAlignment - 1);
			var cave = new CodeCave(_mem, CodeCaveAddress.Value, alignedSize, true);
			CodeCaves.Add(cave);

			_allocatedBytes += alignedSize;

			// Write payload before returning.
			cave.Write(payload);
			return cave;
		}

		/// <summary>
		/// Creates a new <see cref="Detour"/>, managed by the <see cref="CaveManager"/>
		/// <param name="address">The preferred baseline address to start searching from.</param>
		/// <param name="bytesReplaced">The number of bytes being replaced with a JMP to the <see cref="Detour"/>.</param>
		/// <param name="extraSpace">Extra space in memory to allocate to the <see cref="Detour"/>.
		/// Extra space may be automatically added to ensure proper alignment for instructions.</param>
		/// <param name="payload">Custom bytes to write to the <see cref="Detour"/>.</param>
		/// </summary>
		public Detour? CreateDetour(nint address, int bytesReplaced, int extraSpace, ReadOnlySpan<byte> payload)
		{
			// +5 for E9 relative JMP. Does not account for 64 bit absolute JMP instructions.
			var size = payload.Length + extraSpace + 5;
			var CodeCaveAddress = GetCodeCaveAddress(size);

			if (CodeCaveAddress == null)
				return null;

			int alignedSize = (size + (_codeAlignment - 1)) & ~(_codeAlignment - 1);
			var detour = new Detour(_mem, CodeCaveAddress.Value, alignedSize, true);
			Detours.Add(detour);

			_allocatedBytes += alignedSize;

			// Write payload before returning.
			detour.Write(address, bytesReplaced, payload);

			return detour;
		}

		/// <summary>
		/// Closes all instances of <see cref="Detours"/> in the <see cref="CaveManager"/>.
		/// </summary>
		public void CloseCodeCaves()
		{
			foreach (CodeCave cave in Detours)
			{
				cave.Dispose();
			}
			foreach (Detour detour in Detours)
			{
				detour.Dispose();
			}
		}

		/// <summary>
		/// Closes the <see cref="CaveManager"/> along with all of its Detours. CodeCaves should be manually reset before hand.
		/// </summary>
		/// <returns></returns>
		public bool CloseCave()
		{
			CloseCodeCaves();

			return _mem.FreeCave(Address);
		}

		/// <summary>
		/// This is the mandatory IDisposable method. It triggers automatically 
		/// whenever a 'using' block ends. Frees the code cave and closes all <see cref="CodeCave"/>
		/// and <see cref="Detour"/> instances managed by the <see cref="CaveManager"/>
		/// before clearing the <see cref="Detour"/>.
		/// </summary>
		public void Dispose()
		{
			if (_isDisposed)
				return;

			CloseCave();

			_isDisposed = true;
			GC.SuppressFinalize(this);
		}
	}
}
