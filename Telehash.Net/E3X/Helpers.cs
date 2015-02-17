using System;

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
	}
}

