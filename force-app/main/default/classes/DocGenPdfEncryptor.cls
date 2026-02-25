/**
 * @description PDF Revision 4 AES-128-CBC encryption engine.
 *
 *              Implements PDF Reference 1.6, Section 3.5:
 *              - 128-bit key derivation with 50x MD5 hardening
 *              - 20x iterated RC4 for O/U password hash computation
 *              - AES-128-CBC content encryption via native Crypto class
 *              - Per-object key derivation with sAlT extension
 *
 *              SECURITY NOTES:
 *              - Passwords must NEVER be logged or persisted in plain text
 *              - PDF permission restrictions are ADVISORY per the PDF spec;
 *                compliant readers enforce them but not all readers comply
 *              - AES-128-CBC content encryption is genuine strong encryption
 *              - RC4 is used ONLY for password hash derivation (PDF spec mandate)
 *
 * @group DocGen PDF Security
 */
public with sharing class DocGenPdfEncryptor {

    // PDF Standard Password Padding — PDF Spec Table 3.18
    // Fixed constant defined in the specification, identical in every implementation
    @TestVisible
    private static final List<Integer> PASSWORD_PADDING = new List<Integer>{
        0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
        0x64, 0x00, 0x4B, 0x49, 0x43, 0x6B, 0x73, 0x28,
        0x47, 0x69, 0x76, 0x65, 0x4E, 0x23, 0x44, 0x6E,
        0x51, 0x45, 0x62, 0x45, 0x64, 0x6F, 0x47, 0x2F
    };

    private static final Integer KEY_LEN = 16; // 128-bit

    // Permission flags — PDF Reference 1.6, Table 3.20
    public static final Integer PERM_PRINT       = 4;
    public static final Integer PERM_MODIFY      = 8;
    public static final Integer PERM_COPY        = 16;
    public static final Integer PERM_ANNOT       = 32;
    public static final Integer PERM_FILL_FORMS  = 256;
    public static final Integer PERM_EXTRACT_ACC = 512;
    public static final Integer PERM_ASSEMBLE    = 1024;
    public static final Integer PERM_PRINT_HIGH  = 2048;

    // ================================================================
    // Encryption context — holds all derived keys and hashes
    // ================================================================
    public class EncryptionContext {
        public List<Integer> encryptionKey;
        public List<Integer> ownerHash;   // O value (32 bytes)
        public List<Integer> userHash;    // U value (32 bytes)
        public List<Integer> fileId;      // 16-byte unique file identifier
        public Integer permissions;
    }

    // ================================================================
    // Permission builder — deny-all default
    // ================================================================
    public class PermissionSet {
        public Boolean allowPrint     = false;
        public Boolean allowModify    = false;
        public Boolean allowCopy      = false;
        public Boolean allowAnnotate  = false;
        public Boolean allowFillForms = false;
        public Boolean allowAssembly  = false;
        public Boolean allowPrintHigh = false;
        public Boolean allowExtract   = false;

        public Integer toInteger() {
            // Per PDF spec: bits 1-2 = 0, bits 7-8 reserved (1),
            // bits 13-32 = 1 for Rev 3+
            Integer p = -3904;
            if (allowPrint)     p = p | PERM_PRINT | PERM_PRINT_HIGH;
            if (allowModify)    p = p | PERM_MODIFY;
            if (allowCopy)      p = p | PERM_COPY | PERM_EXTRACT_ACC;
            if (allowAnnotate)  p = p | PERM_ANNOT;
            if (allowFillForms) p = p | PERM_FILL_FORMS;
            if (allowAssembly)  p = p | PERM_ASSEMBLE;
            return p;
        }
    }

    // ================================================================
    // Build encryption context from passwords
    // ================================================================
    /**
     * @description Derives all encryption material from passwords.
     *              Caller should null password references after calling.
     * @param userPassword  Password to open (empty string for no open prompt)
     * @param ownerPassword Password for permissions (required)
     * @param perms         Permission flags
     * @return EncryptionContext with keys, hashes, and file ID
     */
    public static EncryptionContext buildContext(
        String userPassword,
        String ownerPassword,
        PermissionSet perms
    ) {
        if (String.isBlank(ownerPassword)) {
            throw new DocGenEncryptionException(
                'Owner password is required for PDF encryption.'
            );
        }

        EncryptionContext ctx = new EncryptionContext();
        ctx.permissions = perms.toInteger();
        ctx.fileId = blobToList(Crypto.generateAesKey(128), 16);

        List<Integer> paddedUser  = padPassword(userPassword);
        List<Integer> paddedOwner = padPassword(ownerPassword);

        ctx.ownerHash     = computeOwnerHashR3(paddedOwner, paddedUser);
        ctx.encryptionKey = computeEncryptionKeyR3(
            paddedUser, ctx.ownerHash, ctx.permissions, ctx.fileId
        );
        ctx.userHash = computeUserHashR3(ctx.encryptionKey, ctx.fileId);

        return ctx;
    }

    // ================================================================
    // AES-128-CBC encryption for a PDF object
    // Returns: IV (16 bytes) + ciphertext
    // ================================================================
    /**
     * @description Encrypts content for a specific PDF object using
     *              AES-128-CBC with per-object key derivation.
     * @param ctx      Encryption context
     * @param data     Plaintext data as Blob
     * @param objectId PDF object number
     * @param genNum   PDF generation number (usually 0)
     * @return IV (16 bytes) prepended to ciphertext
     */
    public static Blob encryptObjectData(
        EncryptionContext ctx, Blob data, Integer objectId, Integer genNum
    ) {
        Blob objKey = deriveObjectKey(ctx.encryptionKey, objectId, genNum);
        Blob iv = Crypto.generateAesKey(128);
        Blob ciphertext = Crypto.encrypt('AES128', objKey, iv, data);
        return concatenateBlobs(iv, ciphertext);
    }

    // ================================================================
    // Algorithm 3.1 — Per-object key with sAlT for AES
    // ================================================================
    @TestVisible
    private static Blob deriveObjectKey(
        List<Integer> baseKey, Integer objectId, Integer genNum
    ) {
        List<Integer> extended = new List<Integer>();
        extended.addAll(baseKey);
        extended.add(objectId & 0xFF);
        extended.add((objectId >> 8) & 0xFF);
        extended.add((objectId >> 16) & 0xFF);
        extended.add(genNum & 0xFF);
        extended.add((genNum >> 8) & 0xFF);
        // sAlT for AES — PDF spec requirement
        extended.add(0x73);
        extended.add(0x41);
        extended.add(0x6C);
        extended.add(0x54);

        Blob md5 = Crypto.generateDigest('MD5', listToBlob(extended));
        return truncateBlob(md5, Math.min(baseKey.size() + 5, 16));
    }

    // ================================================================
    // Algorithm 3.2 Rev 3 — Encryption key, 50x MD5 hardening
    // ================================================================
    @TestVisible
    private static List<Integer> computeEncryptionKeyR3(
        List<Integer> paddedUserPw, List<Integer> ownerHash,
        Integer permissions, List<Integer> fileId
    ) {
        List<Integer> hashInput = new List<Integer>();
        hashInput.addAll(paddedUserPw);
        hashInput.addAll(ownerHash);
        hashInput.add(permissions & 0xFF);
        hashInput.add((permissions >> 8) & 0xFF);
        hashInput.add((permissions >> 16) & 0xFF);
        hashInput.add((permissions >> 24) & 0xFF);
        hashInput.addAll(fileId);

        Blob md5Result = Crypto.generateDigest('MD5', listToBlob(hashInput));
        for (Integer i = 0; i < 50; i++) {
            md5Result = Crypto.generateDigest('MD5', truncateBlob(md5Result, KEY_LEN));
        }
        return blobToList(md5Result, KEY_LEN);
    }

    // ================================================================
    // Algorithm 3.3 Rev 3 — Owner hash, 50x MD5 + 20x RC4
    // ================================================================
    @TestVisible
    private static List<Integer> computeOwnerHashR3(
        List<Integer> paddedOwnerPw, List<Integer> paddedUserPw
    ) {
        Blob ownerMd5 = Crypto.generateDigest('MD5', listToBlob(paddedOwnerPw));
        for (Integer i = 0; i < 50; i++) {
            ownerMd5 = Crypto.generateDigest('MD5', truncateBlob(ownerMd5, KEY_LEN));
        }
        List<Integer> rc4Key = blobToList(ownerMd5, KEY_LEN);
        List<Integer> encrypted = DocGenRC4.encrypt(rc4Key, paddedUserPw);
        for (Integer round = 1; round <= 19; round++) {
            List<Integer> xorKey = new List<Integer>();
            for (Integer k = 0; k < KEY_LEN; k++) {
                xorKey.add(rc4Key[k] ^ round);
            }
            encrypted = DocGenRC4.encrypt(xorKey, encrypted);
        }
        return encrypted;
    }

    // ================================================================
    // Algorithm 3.5 Rev 3 — User hash, iterated RC4
    // ================================================================
    @TestVisible
    private static List<Integer> computeUserHashR3(
        List<Integer> encryptionKey, List<Integer> fileId
    ) {
        List<Integer> hashInput = new List<Integer>();
        hashInput.addAll(PASSWORD_PADDING);
        hashInput.addAll(fileId);
        Blob md5Result = Crypto.generateDigest('MD5', listToBlob(hashInput));
        List<Integer> md5Bytes = blobToList(md5Result, 16);
        List<Integer> encrypted = DocGenRC4.encrypt(encryptionKey, md5Bytes);
        for (Integer round = 1; round <= 19; round++) {
            List<Integer> xorKey = new List<Integer>();
            for (Integer k = 0; k < encryptionKey.size(); k++) {
                xorKey.add(encryptionKey[k] ^ round);
            }
            encrypted = DocGenRC4.encrypt(xorKey, encrypted);
        }
        while (encrypted.size() < 32) {
            encrypted.add(0);
        }
        return encrypted;
    }

    // ================================================================
    // Password padding — Algorithm 3.2 step (a)
    // ================================================================
    @TestVisible
    private static List<Integer> padPassword(String password) {
        List<Integer> result = new List<Integer>();
        if (String.isNotBlank(password)) {
            for (Integer i = 0; i < Math.min(password.length(), 32); i++) {
                result.add(password.charAt(i) & 0xFF);
            }
        }
        Integer padStart = result.size();
        for (Integer i = 0; i < 32 - padStart; i++) {
            result.add(PASSWORD_PADDING[i]);
        }
        return result;
    }

    // ================================================================
    // Blob utilities
    // ================================================================
    public static List<Integer> blobToList(Blob b, Integer len) {
        String hex = EncodingUtil.convertToHex(b);
        List<Integer> result = new List<Integer>();
        for (Integer i = 0; i < Math.min(len * 2, hex.length()); i += 2) {
            result.add(hexPairToInt(hex.substring(i, i + 2)));
        }
        return result;
    }

    public static Blob listToBlob(List<Integer> bytes) {
        List<String> parts = new List<String>();
        String hc = '0123456789abcdef';
        for (Integer b : bytes) {
            parts.add(
                hc.substring(b >> 4, (b >> 4) + 1) +
                hc.substring(b & 0x0F, (b & 0x0F) + 1)
            );
        }
        return EncodingUtil.convertFromHex(String.join(parts, ''));
    }

    public static String listToHex(List<Integer> bytes) {
        List<String> parts = new List<String>();
        String hc = '0123456789abcdef';
        for (Integer b : bytes) {
            parts.add(
                hc.substring(b >> 4, (b >> 4) + 1) +
                hc.substring(b & 0x0F, (b & 0x0F) + 1)
            );
        }
        return String.join(parts, '');
    }

    private static Integer hexPairToInt(String hex) {
        String h = '0123456789abcdef';
        return h.indexOf(hex.substring(0, 1).toLowerCase()) * 16 +
               h.indexOf(hex.substring(1, 2).toLowerCase());
    }

    private static Blob truncateBlob(Blob b, Integer len) {
        String hex = EncodingUtil.convertToHex(b);
        return EncodingUtil.convertFromHex(hex.substring(0, len * 2));
    }

    public static Blob concatenateBlobs(Blob a, Blob b) {
        return EncodingUtil.convertFromHex(
            EncodingUtil.convertToHex(a) + EncodingUtil.convertToHex(b)
        );
    }

    public class DocGenEncryptionException extends Exception {}
}
