package com.shamir;

import org.graalvm.compiler.bytecode.BytecodeStream;


/**
 * BytesBuilder encapsulates a 2D array of bytes with the given dimensions that you're building, 
 * row-by-row or column-by-column. This also encapsulates the counter for each row or column
 * you're adding the data to, making it so the surrounding code doesn't need to keep track of it.
 * 
 * This is custom built for Scheme, since it creates 2D byte arrays twice, and the build code is
 * confusing, especially when tracking the index to add the data to. So this class was created to
 * encapsulate that.
 */
class BytesBuilder {
    private int current = 0;
    private byte[][] bytes;
    private boolean byRow;

    /**
     * Creates a BytesBuilder of size dim1 x dim2. The byRow parameter determines
     * if the automatic index updates the first index (true) or the second (false).
     * @param dim1 size of the first dimension of the array
     * @param dim2 size of the second dimension of the array
     * @param byRow update the automatic index for the first index (true) or second index (false)
     */
    protected BytesBuilder(int dim1, int dim2, boolean byRow) {
        bytes = new byte[dim1][dim2];
        this.byRow = byRow;
    }

    /**
     * Creates a BytesBuilder where the first index of the 2D array is automatically
     * incremented with each call to add(), and the given data is split up between the
     * second indices.
     * @param dim1 size of the first dimension of the array
     * @param dim2 size of the second dimension of the array
     * @return new BytesBuilder that auto-increments the first index
     */
    public static BytesBuilder autoIndexFirst(int dim1, int dim2) {
        return new BytesBuilder(dim1, dim2, true);
    }

    /**
     * Creates a BytesBuilder where the second index of the 2D array is automatically
     * incremented with each call to add(), and the given data is split up between the
     * first indices.
     * @param dim1
     * @param dim2
     * @return
     */
    public static BytesBuilder autoIndexSecond(int dim1, int dim2) {
        return new BytesBuilder(dim1, dim2, false);
    }

    /**
     * Add the array of bytes to this collection at the current index, then update the
     * index for the next addition
     * @param pieces bytes to add to the bytes array
     * @throws ArrayOutOfBoundsException
     */
    public void add(byte... pieces) {
        for (int i = 0; i < pieces.length; i++) {
          addPiece(i, pieces[i]);
        }
        current++;
    }

    private void addPiece(int i, byte piece) {
        if ( byRow ) {
            bytes[current][i] = piece;
        }
        else {
            bytes[i][current] = piece;
        }
    }

    public byte[][] toBytes() { return bytes; }
}