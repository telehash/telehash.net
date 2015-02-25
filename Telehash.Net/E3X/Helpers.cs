using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Telehash.E3X
{
	public class Helpers
	{
		public static byte[] Fold(byte[] foldingBytes, int folds = 1)
		{
			// It must be an even length
			if (foldingBytes.Length % 2 != 0) {
				return null;
			}

			byte[] foldedBuffer = null;
			for (int i = 0; i < folds; ++i) {
				foldedBuffer = FoldOnce (foldedBuffer == null ? foldingBytes : foldedBuffer);
			}
			return foldedBuffer;
		}

		public static byte[] FoldOnce(byte[] foldingBytes)
		{
			// It must be an even length
			if (foldingBytes.Length % 2 != 0) {
				return null;
			}
			
			int halfLength = foldingBytes.Length / 2;
			byte[] outBuffer = new byte[halfLength];
			for (int i = 0; i < halfLength; ++i) {
				outBuffer [i] = (byte)(foldingBytes [i] ^ foldingBytes [i + halfLength]);
			}
			
			return outBuffer;
		}


		// From http://stackoverflow.com/questions/623104/byte-to-hex-string/18574846#18574846
		public static string[] HexTbl = Enumerable.Range(0, 256).Select(v => v.ToString("x2")).ToArray();
		public static string ToHex(IEnumerable<byte> array)
		{
			StringBuilder s = new StringBuilder();
			foreach (var v in array)
				s.Append(HexTbl[v]);
			return s.ToString();
		}
		public static string ToHex(byte[] array)
		{
			StringBuilder s = new StringBuilder(array.Length*2);
			foreach (var v in array)
				s.Append(HexTbl[v]);
			return s.ToString();
		}
	}
}

