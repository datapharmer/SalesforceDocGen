/**
 * @description RC4 stream cipher used EXCLUSIVELY for PDF password hash
 *              derivation (O and U values per PDF Reference 1.6 Section 3.5).
 *              Content encryption uses AES-128-CBC via the native Crypto class.
 *
 *              RC4 is mandated by the PDF specification for computing password
 *              verification hashes even when AES encrypts actual content (Rev 4).
 *
 * @group DocGen PDF Security
 */
public with sharing class DocGenRC4 {

    /**
     * @description Encrypts or decrypts data using RC4. RC4 is symmetric —
     *              the same operation encrypts and decrypts.
     * @param key  Encryption key as byte values (0-255)
     * @param data Data to process as byte values (0-255)
     * @return     Processed output as byte values
     */
    public static List<Integer> encrypt(List<Integer> key, List<Integer> data) {
        // Key Scheduling Algorithm (KSA)
        List<Integer> s = new List<Integer>();
        for (Integer i = 0; i < 256; i++) {
            s.add(i);
        }

        Integer j = 0;
        Integer keySize = key.size();
        for (Integer i = 0; i < 256; i++) {
            j = Math.mod(j + s[i] + key[Math.mod(i, keySize)], 256);
            Integer tmp = s[i];
            s.set(i, s[j]);
            s.set(j, tmp);
        }

        // Pseudo-Random Generation Algorithm (PRGA)
        List<Integer> output = new List<Integer>();
        Integer ii = 0;
        Integer jj = 0;
        for (Integer n = 0; n < data.size(); n++) {
            ii = Math.mod(ii + 1, 256);
            jj = Math.mod(jj + s[ii], 256);
            Integer tmp = s[ii];
            s.set(ii, s[jj]);
            s.set(jj, tmp);
            output.add(data[n] ^ s[Math.mod(s[ii] + s[jj], 256)]);
        }
        return output;
    }
}
