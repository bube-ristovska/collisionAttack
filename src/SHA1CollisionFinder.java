import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;

public class SHA1CollisionFinder {
    public static void main(String[] args) {
        System.out.println("Enter your password, don't worry is hashed with SHA1");
        Scanner sc = new Scanner(System.in);
        String inputString = sc.nextLine();

        SHA1 sha1 = new SHA1();
        sha1.update(inputString.getBytes());
        byte[] inputHash = sha1.digest();
        System.out.println("This is your hash: " + bytesToHex(inputHash));
        String filename = "C:\\Users\\risto\\IdeaProjects\\collisionAttack\\src\\passwords";

        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            int lineNumber = 0;

            while ((line = br.readLine()) != null) {
                lineNumber++;

                sha1.reset();
                sha1.update(line.getBytes());
                byte[] lineHash = sha1.digest();
                System.out.println( lineNumber + ".Comparing hash: " + bytesToHex(inputHash) + " and hash " + bytesToHex(lineHash));

                if (MessageDigest.isEqual(inputHash, lineHash)) {
                    System.out.println("Collision found at line " + lineNumber + ":");
                    System.out.println("Your hash was " + bytesToHex(inputHash));
                    System.out.println("The same hash was found for string: " + line);
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }
}
