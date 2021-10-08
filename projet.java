public class Projet {
    public static void main(String[] args){
        int v = (int) 0xd4c3b2a1;
        int swapped = ((v >> 16) & 0xffff) | ((v & 0xffff) << 16);
		System.out.println(Integer.toHexString(swapped));
	}

    public static String reverseHex(String originalHex) {
        // TODO: Validation that the length is even
        int lengthInBytes = originalHex.length() / 2;
        char[] chars = new char[lengthInBytes * 2];
        for (int index = 0; index < lengthInBytes; index++) {
            int reversedIndex = lengthInBytes - 1 - index;
            chars[reversedIndex * 2] = originalHex.charAt(index * 2);
            chars[reversedIndex * 2 + 1] = originalHex.charAt(index * 2 + 1);
        }
        return new String(chars);
    }
}