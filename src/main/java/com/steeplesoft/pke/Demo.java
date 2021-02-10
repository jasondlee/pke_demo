package com.steeplesoft.pke;

public class Demo {
    public static void main(String[] args) {
        Client1 client1 = new Client1();
        Client2 client2 = new Client2();

        String sampleText = "This is some sample text.";
        String encrypted = client1.encryptText(sampleText, client2.getPublicKey());

        System.out.println(encrypted);
        String decrypted = client2.decryptText(encrypted);
        System.out.println(decrypted);
        assert(sampleText.equals(decrypted));
    }
}
