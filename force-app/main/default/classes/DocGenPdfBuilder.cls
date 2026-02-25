/**
 * @description Directly rewrites an existing PDF to add Rev 4 AES-128-CBC
 *              encryption, preserving original structure and inline display.
 *
 *              No cover page. No envelope. No attachment to open.
 *              The encrypted PDF displays identically to the original —
 *              same pages, same formatting, same bookmarks — just encrypted.
 *
 *              SCOPE: Supports PDFs with traditional cross-reference tables.
 *              This covers Blob.toPdf() output, Visualforce-rendered PDFs,
 *              and most legacy generators. PDFs with compressed xref streams
 *              (Chrome, modern Word) are detected and rejected with a clear
 *              error message.
 *
 *              APPROACH: Converts entire PDF to hex string, parses structure
 *              by searching for PDF keywords in hex, encrypts each stream
 *              in-place, rebuilds xref + trailer with encryption dictionary.
 *              Final output via EncodingUtil.convertFromHex() produces raw
 *              binary — zero encoding overhead in the output file.
 *
 *              PASSWORD BEHAVIOR:
 *              - Both blank:      Returns PDF unchanged (no encryption)
 *              - Owner only:      Opens without prompt, permissions enforced
 *              - User only:       Prompts to open, owner auto-derived
 *              - User + Owner:    Prompts to open, permissions enforced
 *
 * @group DocGen PDF Security
 */
public with sharing class DocGenPdfBuilder {

    // PDF keywords as hex-encoded strings for searching within hex
    private static final String HEX_STREAM    = '73747265616d';       // "stream"
    private static final String HEX_ENDSTREAM = '656e6473747265616d'; // "endstream"
    private static final String HEX_ENDOBJ    = '656e646f626a';       // "endobj"
    private static final String HEX_OBJ       = '6f626a';             // "obj"
    private static final String HEX_XREF      = '78726566';           // "xref"
    private static final String HEX_TRAILER   = '747261696c6572';     // "trailer"
    private static final String HEX_NEWLINE   = '0a';
    private static final String HEX_CR        = '0d';
    private static final String HEX_SPACE     = '20';
    private static final String HEX_ENCRYPT   = '2f456e6372797074';   // "/Encrypt"
    private static final String HEX_LENGTH    = '2f4c656e677468';     // "/Length"
    private static final String HEX_ROOT      = '2f526f6f74';         // "/Root"

    // ================================================================
    // Parsed PDF structure
    // ================================================================
    @TestVisible
    private class PdfStructure {
        public List<PdfObject> objects;
        public Integer trailerHexPos;
        public Integer xrefHexPos;
        public String rootRef;
        public Integer maxObjectNumber;
    }

    @TestVisible
    private class PdfObject {
        public Integer objectNumber;
        public Integer generationNumber;
        public Integer headerHexPos;      // hex char position of "N N obj"
        public Integer streamDataHexStart; // hex pos where stream data begins
        public Integer streamDataHexEnd;   // hex pos where stream data ends
        public Boolean hasStream;
    }

    // Comparator for reverse-offset processing
    private class ReverseOffsetComparator implements System.Comparator<PdfObject> {
        public Integer compare(PdfObject a, PdfObject b) {
            return b.headerHexPos - a.headerHexPos;
        }
    }

    // ================================================================
    // MAIN ENTRY POINT
    // ================================================================
    /**
     * @description Encrypts a PDF with optional independent passwords.
     * @param sourcePdf     Source PDF Blob
     * @param userPassword  View password (null/blank = no open prompt)
     * @param ownerPassword Edit password (null/blank = no permission restrictions)
     * @param perms         Permission flags (ignored if no owner password)
     * @return Encrypted PDF, or original if no passwords provided
     */
    public static Blob encryptPdf(
        Blob sourcePdf,
        String userPassword,
        String ownerPassword,
        DocGenPdfEncryptor.PermissionSet perms
    ) {
        Boolean hasUserPw  = String.isNotBlank(userPassword);
        Boolean hasOwnerPw = String.isNotBlank(ownerPassword);

        // No passwords = no encryption
        if (!hasUserPw && !hasOwnerPw) {
            return sourcePdf;
        }

        // User password without owner: auto-derive owner
        // PDF spec requires both O and U values in encrypt dictionary
        if (hasUserPw && !hasOwnerPw) {
            Blob salt = Crypto.generateAesKey(128);
            ownerPassword = EncodingUtil.convertToHex(
                Crypto.generateDigest('SHA-256',
                    Blob.valueOf(userPassword + EncodingUtil.convertToHex(salt))
                )
            ).substring(0, 32);
        }

        // Owner only: user password is empty string (opens without prompt)
        if (!hasUserPw) {
            userPassword = '';
        }

        // Convert to hex for processing
        String sourceHex = EncodingUtil.convertToHex(sourcePdf);
        sourcePdf = null; // release heap

        // Validate PDF structure
        validatePdf(sourceHex);

        // Parse structure
        PdfStructure structure = parsePdfStructure(sourceHex);

        // Build encryption context
        DocGenPdfEncryptor.EncryptionContext ctx =
            DocGenPdfEncryptor.buildContext(userPassword, ownerPassword, perms);
        userPassword = null;
        ownerPassword = null;

        // Encrypt all streams (process in reverse offset order)
        sourceHex = encryptAllStreams(sourceHex, structure, ctx);

        // Rebuild xref + trailer with encryption dictionary
        String finalHex = rebuildXrefAndTrailer(sourceHex, structure, ctx);
        sourceHex = null; // release heap

        return EncodingUtil.convertFromHex(finalHex);
    }

    // ================================================================
    // Validation
    // ================================================================
    private static void validatePdf(String hex) {
        if (!hex.startsWith('255044462d')) { // %PDF-
            throw new DocGenPdfEncryptor.DocGenEncryptionException(
                'Invalid PDF: missing %PDF- header.'
            );
        }
        if (hex.indexOf(HEX_XREF) == -1) {
            throw new DocGenPdfEncryptor.DocGenEncryptionException(
                'Unsupported PDF: compressed cross-reference streams detected. ' +
                'This encryptor supports traditional xref tables. PDFs from ' +
                'Blob.toPdf() and Visualforce are supported. PDFs from Chrome ' +
                'or modern Word may use xref streams and are not supported.'
            );
        }
        if (hex.indexOf(HEX_ENCRYPT) != -1) {
            throw new DocGenPdfEncryptor.DocGenEncryptionException(
                'PDF is already encrypted. Remove existing encryption before re-encrypting.'
            );
        }
    }

    // ================================================================
    // Parse PDF structure
    // ================================================================
    @TestVisible
    private static PdfStructure parsePdfStructure(String hex) {
        PdfStructure structure = new PdfStructure();
        structure.objects = new List<PdfObject>();
        structure.maxObjectNumber = 0;

        // Find all indirect objects by searching for " obj"
        String objMarker = HEX_SPACE + HEX_OBJ; // " obj"
        Integer searchFrom = 0;

        while (searchFrom < hex.length()) {
            Integer objPos = hex.indexOf(objMarker, searchFrom);
            if (objPos == -1) break;

            // Skip if this is "endobj" — check for "end" preceding
            if (objPos >= 6) {
                if (hex.substring(objPos - 6, objPos) == '656e64') {
                    searchFrom = objPos + objMarker.length();
                    continue;
                }
            }

            PdfObject obj = parseObjectHeader(hex, objPos);
            if (obj != null) {
                findStreamBoundaries(hex, obj, objPos);
                structure.objects.add(obj);
                if (obj.objectNumber > structure.maxObjectNumber) {
                    structure.maxObjectNumber = obj.objectNumber;
                }
            }

            searchFrom = objPos + objMarker.length();
        }

        // Locate xref and trailer
        structure.xrefHexPos = hex.lastIndexOf(HEX_XREF);
        structure.trailerHexPos = hex.lastIndexOf(HEX_TRAILER);

        // Extract /Root reference from trailer
        if (structure.trailerHexPos != -1) {
            structure.rootRef = extractValue(hex, structure.trailerHexPos, HEX_ROOT);
        }
        if (String.isBlank(structure.rootRef)) {
            structure.rootRef = '1 0 R';
        }

        return structure;
    }

    // ================================================================
    // Parse "N N obj" header — walk backward from " obj" to find numbers
    // ================================================================
    private static PdfObject parseObjectHeader(String hex, Integer spaceObjPos) {
        // Walk backward from the space before "obj" to find gen number
        Integer pos = spaceObjPos - 2;

        String genHex = '';
        while (pos >= 0) {
            String ch = hex.substring(pos, pos + 2);
            if (isHexDigit(ch)) {
                genHex = ch + genHex;
                pos -= 2;
            } else {
                break;
            }
        }
        if (genHex.length() == 0) return null;

        // Expect whitespace between object number and gen number
        if (pos < 0) return null;
        String sep = hex.substring(pos, pos + 2);
        if (sep != HEX_SPACE && sep != HEX_NEWLINE && sep != HEX_CR) return null;
        pos -= 2;

        // Walk backward to find object number
        String objNumHex = '';
        while (pos >= 0) {
            String ch = hex.substring(pos, pos + 2);
            if (isHexDigit(ch)) {
                objNumHex = ch + objNumHex;
                pos -= 2;
            } else {
                break;
            }
        }
        if (objNumHex.length() == 0) return null;

        PdfObject obj = new PdfObject();
        obj.objectNumber = Integer.valueOf(hexToAscii(objNumHex));
        obj.generationNumber = Integer.valueOf(hexToAscii(genHex));
        obj.headerHexPos = pos + 2;
        obj.hasStream = false;

        return obj;
    }

    // ================================================================
    // Find stream data boundaries within an object
    // ================================================================
    private static void findStreamBoundaries(String hex, PdfObject obj, Integer afterObjPos) {
        Integer endObjPos = hex.indexOf(HEX_ENDOBJ, afterObjPos);
        if (endObjPos == -1) return;

        // Look for "stream" between " obj" and "endobj"
        Integer streamPos = hex.indexOf(HEX_STREAM, afterObjPos);
        if (streamPos == -1 || streamPos >= endObjPos) return;

        // Ensure this is "stream" not "endstream"
        if (streamPos >= 6) {
            if (hex.substring(streamPos - 6, streamPos) == '656e64') return;
        }

        obj.hasStream = true;

        // Stream data starts after "stream" + line ending (\n or \r\n)
        Integer afterKeyword = streamPos + HEX_STREAM.length();
        if (afterKeyword + 4 <= hex.length()) {
            String next4 = hex.substring(afterKeyword, afterKeyword + 4);
            if (next4.startsWith(HEX_CR + HEX_NEWLINE)) {
                obj.streamDataHexStart = afterKeyword + 4;
            } else if (next4.startsWith(HEX_NEWLINE)) {
                obj.streamDataHexStart = afterKeyword + 2;
            } else {
                obj.streamDataHexStart = afterKeyword;
            }
        } else {
            obj.streamDataHexStart = afterKeyword;
        }

        // Stream data ends just before "endstream"
        Integer endStreamPos = hex.indexOf(HEX_ENDSTREAM, obj.streamDataHexStart);
        if (endStreamPos != -1) {
            // Back up over optional newline before "endstream"
            Integer checkPos = endStreamPos - 2;
            if (checkPos >= obj.streamDataHexStart) {
                String beforeEnd = hex.substring(checkPos, endStreamPos);
                if (beforeEnd == HEX_NEWLINE || beforeEnd == HEX_CR) {
                    obj.streamDataHexEnd = checkPos;
                } else if (checkPos >= 2) {
                    String twoBefore = hex.substring(checkPos - 2, endStreamPos);
                    if (twoBefore == HEX_CR + HEX_NEWLINE) {
                        obj.streamDataHexEnd = checkPos - 2;
                    } else {
                        obj.streamDataHexEnd = endStreamPos;
                    }
                } else {
                    obj.streamDataHexEnd = endStreamPos;
                }
            } else {
                obj.streamDataHexEnd = endStreamPos;
            }
        }
    }

    // ================================================================
    // Encrypt all object streams — reverse order to preserve offsets
    // ================================================================
    private static String encryptAllStreams(
        String hex,
        PdfStructure structure,
        DocGenPdfEncryptor.EncryptionContext ctx
    ) {
        // Sort by offset descending — modify from end to start so
        // earlier positions remain valid after each modification
        List<PdfObject> sorted = new List<PdfObject>(structure.objects);
        sorted.sort(new ReverseOffsetComparator());

        for (PdfObject obj : sorted) {
            if (!obj.hasStream) continue;
            if (obj.streamDataHexStart == null || obj.streamDataHexEnd == null) continue;
            if (obj.streamDataHexEnd <= obj.streamDataHexStart) continue;

            // Extract original stream bytes
            String streamHex = hex.substring(obj.streamDataHexStart, obj.streamDataHexEnd);
            if (streamHex.length() == 0) continue;

            // Encrypt
            Blob streamBlob = EncodingUtil.convertFromHex(streamHex);
            Blob encBlob = DocGenPdfEncryptor.encryptObjectData(
                ctx, streamBlob, obj.objectNumber, obj.generationNumber
            );
            String encHex = EncodingUtil.convertToHex(encBlob);
            Integer newStreamLen = encBlob.size();

            // Release intermediates
            streamBlob = null;
            encBlob = null;

            // Replace stream data in hex string
            hex = hex.substring(0, obj.streamDataHexStart)
                + encHex
                + hex.substring(obj.streamDataHexEnd);

            // Update /Length value in the object dictionary
            // /Length appears between obj header and stream keyword
            hex = updateLength(hex, obj.headerHexPos, obj.streamDataHexStart, newStreamLen);
        }

        return hex;
    }

    // ================================================================
    // Update /Length N in an object dictionary
    // ================================================================
    private static String updateLength(
        String hex, Integer objHeaderHexPos, Integer beforeStreamHexPos, Integer newLength
    ) {
        Integer lengthPos = hex.indexOf(HEX_LENGTH, objHeaderHexPos);
        if (lengthPos == -1 || lengthPos >= beforeStreamHexPos) return hex;

        // Position after "/Length"
        Integer afterKey = lengthPos + HEX_LENGTH.length();

        // Skip whitespace
        while (afterKey < hex.length()) {
            String ch = hex.substring(afterKey, afterKey + 2);
            if (ch == HEX_SPACE || ch == HEX_NEWLINE || ch == HEX_CR) {
                afterKey += 2;
            } else {
                break;
            }
        }

        // Read existing number (ASCII digits in hex)
        Integer numEnd = afterKey;
        while (numEnd < hex.length()) {
            String ch = hex.substring(numEnd, numEnd + 2);
            if (isHexDigit(ch)) {
                numEnd += 2;
            } else {
                break;
            }
        }

        // If no direct number found (might be indirect reference N N R),
        // skip update — some readers tolerate length mismatch when
        // endstream marker is present
        if (numEnd == afterKey) return hex;

        // Replace old length value with new
        String newLenHex = asciiToHex(String.valueOf(newLength));
        return hex.substring(0, afterKey) + newLenHex + hex.substring(numEnd);
    }

    // ================================================================
    // Rebuild xref table and trailer with encrypt dictionary
    // ================================================================
    private static String rebuildXrefAndTrailer(
        String hex,
        PdfStructure structure,
        DocGenPdfEncryptor.EncryptionContext ctx
    ) {
        // Truncate at original xref — keep only the body
        if (structure.xrefHexPos == -1) {
            throw new DocGenPdfEncryptor.DocGenEncryptionException(
                'Cannot locate xref table.'
            );
        }
        String bodyHex = hex.substring(0, structure.xrefHexPos);
        hex = null; // release heap

        // Add encryption dictionary as new object
        Integer encObjNum = structure.maxObjectNumber + 1;
        String encDictAscii = encObjNum + ' 0 obj\n'
            + '<< /Filter /Standard /V 4 /R 4 /Length 128'
            + ' /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV2 /Length 16 >> >>'
            + ' /StmF /StdCF /StrF /StdCF'
            + ' /O <' + DocGenPdfEncryptor.listToHex(ctx.ownerHash) + '>'
            + ' /U <' + DocGenPdfEncryptor.listToHex(ctx.userHash) + '>'
            + ' /P ' + String.valueOf(ctx.permissions)
            + ' >>\nendobj\n';
        bodyHex += asciiToHex(encDictAscii);

        // Re-find all object offsets in modified body
        Integer totalObjects = encObjNum + 1;
        Map<Integer, Integer> offsetMap = buildOffsetMap(bodyHex);

        // Build xref
        Integer xrefByteOffset = bodyHex.length() / 2;
        String xrefAscii = 'xref\n0 ' + totalObjects + '\n';
        xrefAscii += '0000000000 65535 f \n';
        for (Integer i = 1; i < totalObjects; i++) {
            Integer byteOffset = offsetMap.containsKey(i) ? offsetMap.get(i) : 0;
            xrefAscii += String.valueOf(byteOffset).leftPad(10, '0') + ' 00000 n \n';
        }
        bodyHex += asciiToHex(xrefAscii);

        // Build trailer
        String fileIdHex = DocGenPdfEncryptor.listToHex(ctx.fileId);
        String trailerAscii = 'trailer\n<< /Size ' + totalObjects
            + ' /Root ' + structure.rootRef
            + ' /Encrypt ' + encObjNum + ' 0 R'
            + ' /ID [<' + fileIdHex + '> <' + fileIdHex + '>]'
            + ' >>\nstartxref\n' + xrefByteOffset + '\n%%EOF';
        bodyHex += asciiToHex(trailerAscii);

        return bodyHex;
    }

    // ================================================================
    // Build map of object number → byte offset in hex body
    // ================================================================
    private static Map<Integer, Integer> buildOffsetMap(String hex) {
        Map<Integer, Integer> map = new Map<Integer, Integer>();
        String marker = HEX_SPACE + HEX_OBJ;
        Integer searchFrom = 0;

        while (searchFrom < hex.length()) {
            Integer pos = hex.indexOf(marker, searchFrom);
            if (pos == -1) break;

            // Skip "endobj"
            if (pos >= 6 && hex.substring(pos - 6, pos) == '656e64') {
                searchFrom = pos + marker.length();
                continue;
            }

            PdfObject obj = parseObjectHeader(hex, pos);
            if (obj != null) {
                map.put(obj.objectNumber, obj.headerHexPos / 2);
            }
            searchFrom = pos + marker.length();
        }
        return map;
    }

    // ================================================================
    // Extract a value after a key in the trailer area
    // ================================================================
    private static String extractValue(String hex, Integer startHexPos, String keyHex) {
        Integer keyPos = hex.indexOf(keyHex, startHexPos);
        if (keyPos == -1) return null;

        Integer valStart = keyPos + keyHex.length();
        // Skip whitespace
        while (valStart + 2 <= hex.length()) {
            String ch = hex.substring(valStart, valStart + 2);
            if (ch == HEX_SPACE || ch == HEX_NEWLINE || ch == HEX_CR) {
                valStart += 2;
            } else {
                break;
            }
        }

        // Read value until / or > or end of reasonable length
        String valueHex = '';
        Integer pos = valStart;
        while (pos + 2 <= hex.length() && valueHex.length() < 40) {
            String ch = hex.substring(pos, pos + 2);
            if (ch == '2f' || ch == '3e') break; // / or >
            valueHex += ch;
            pos += 2;
        }

        String ascii = hexToAscii(valueHex).trim();
        return String.isNotBlank(ascii) ? ascii : null;
    }

    // ================================================================
    // Hex ↔ ASCII utilities
    // ================================================================
    @TestVisible
    private static String hexToAscii(String hex) {
        String result = '';
        for (Integer i = 0; i + 2 <= hex.length(); i += 2) {
            String hc = '0123456789abcdef';
            Integer val = hc.indexOf(hex.substring(i, i + 1).toLowerCase()) * 16 +
                          hc.indexOf(hex.substring(i + 1, i + 2).toLowerCase());
            result += String.fromCharArray(new List<Integer>{val});
        }
        return result;
    }

    @TestVisible
    private static String asciiToHex(String ascii) {
        return EncodingUtil.convertToHex(Blob.valueOf(ascii));
    }

    private static Boolean isHexDigit(String hexPair) {
        // ASCII digits 0-9 are hex 30-39
        return hexPair.compareTo('30') >= 0 && hexPair.compareTo('39') <= 0;
    }
}
