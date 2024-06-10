import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SHA1 {
    private static final int SHA1_BLOCK_SIZE = 64; // Block size in bytes
    private static final int SHA1_HASH_SIZE = 20;  // Hash size in bytes

    private int[] intermediateHash;
    private long length;              // Total length of the input in bits
    private int messageBlockIndex;    // Index into the message block array
    private byte[] messageBlock;      // Message block array
    private boolean computed;

    public SHA1() {
        intermediateHash = new int[SHA1_HASH_SIZE / 4];
        messageBlock = new byte[SHA1_BLOCK_SIZE];
        reset();
    }

    public void reset() {
        length = 0;
        messageBlockIndex = 0;
        computed = false;

        intermediateHash[0] = 0x67452301;
        intermediateHash[1] = 0xEFCDAB89;
        intermediateHash[2] = 0x98BADCFE;
        intermediateHash[3] = 0x10325476;
        intermediateHash[4] = 0xC3D2E1F0;
    }

    public void update(byte[] data) {
        if (computed) {
            throw new IllegalStateException("Hash already computed. Please reset before updating.");
        }

        for (byte b : data) {
            messageBlock[messageBlockIndex++] = b;
            length += 8;

            if (messageBlockIndex == SHA1_BLOCK_SIZE) {
                processMessageBlock();
                messageBlockIndex = 0;
            }
        }
    }

    public byte[] digest() {
        if (computed) {
            throw new IllegalStateException("Hash already computed. Please reset before computing again.");
        }

        padMessage();
        processMessageBlock();

        byte[] hash = new byte[SHA1_HASH_SIZE];
        ByteBuffer buffer = ByteBuffer.allocate(SHA1_HASH_SIZE).order(ByteOrder.BIG_ENDIAN);
        for (int h : intermediateHash) {
            buffer.putInt(h);
        }
        buffer.flip();
        buffer.get(hash);

        computed = true;
        return hash;
    }

    private void padMessage() {
        // Pad message with 0x80 then 0x00 bytes until the length is 56 bytes mod 64
        if (messageBlockIndex > 55) {
            messageBlock[messageBlockIndex++] = (byte) 0x80;
            while (messageBlockIndex < SHA1_BLOCK_SIZE) {
                messageBlock[messageBlockIndex++] = 0;
            }
            processMessageBlock();
            while (messageBlockIndex < 56) {
                messageBlock[messageBlockIndex++] = 0;
            }
        } else {
            messageBlock[messageBlockIndex++] = (byte) 0x80;
            while (messageBlockIndex < 56) {
                messageBlock[messageBlockIndex++] = 0;
            }
        }

        // Append the message length in bits as a 64-bit big-endian integer
        ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(length);
        buffer.flip();
        buffer.get(messageBlock, 56, 8);
    }

    private void processMessageBlock() {
        int[] W = new int[80];

        for (int t = 0; t < 16; t++) {
            W[t] = ((messageBlock[t * 4] & 0xFF) << 24) |
                    ((messageBlock[t * 4 + 1] & 0xFF) << 16) |
                    ((messageBlock[t * 4 + 2] & 0xFF) << 8) |
                    (messageBlock[t * 4 + 3] & 0xFF);
        }

        // SHA-1: XOR and rotate the previous 16 words
        for (int t = 16; t < 80; t++) {
            W[t] = leftRotate(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
        }

        int A = intermediateHash[0];
        int B = intermediateHash[1];
        int C = intermediateHash[2];
        int D = intermediateHash[3];
        int E = intermediateHash[4];

        for (int t = 0; t < 20; t++) {
            int temp = leftRotate(A, 5) + choose(B, C, D) + E + W[t] + 0x5A827999;
            E = D;
            D = C;
            C = leftRotate(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 20; t < 40; t++) {
            int temp = leftRotate(A, 5) + parity(B, C, D) + E + W[t] + 0x6ED9EBA1;
            E = D;
            D = C;
            C = leftRotate(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 40; t < 60; t++) {
            int temp = leftRotate(A, 5) + majority(B, C, D) + E + W[t] + 0x8F1BBCDC;
            E = D;
            D = C;
            C = leftRotate(B, 30);
            B = A;
            A = temp;
        }

        for (int t = 60; t < 80; t++) {
            int temp = leftRotate(A, 5) + parity(B, C, D) + E + W[t] + 0xCA62C1D6;
            E = D;
            D = C;
            C = leftRotate(B, 30);
            B = A;
            A = temp;
        }

        intermediateHash[0] += A;
        intermediateHash[1] += B;
        intermediateHash[2] += C;
        intermediateHash[3] += D;
        intermediateHash[4] += E;

        messageBlockIndex = 0;
    }

    private int leftRotate(int x, int bits) {
        return (x << bits) | (x >>> (32 - bits));
    }

    private int choose(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }

    private int majority(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private int parity(int x, int y, int z) {
        return x ^ y ^ z;
    }

    public static void main(String[] args) {
        SHA1 sha1 = new SHA1();
        String input = "abc";
        sha1.update(input.getBytes());
        byte[] hash = sha1.digest();

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02X", b));

        }
        System.out.println("Message digest SHA1 = " + hexString.toString().trim());
    }
}
