/**
 * @description Comprehensive tests for DocGen PDF encryption.
 *              Covers cryptographic correctness, PDF rewriting,
 *              password independence, governor limits, async handling,
 *              and error paths.
 *
 * @group DocGen PDF Security
 */
@IsTest
private class DocGenPdfEncryptorTest {

    // ================================================================
    // Minimal valid PDF for rewriter tests
    // ================================================================
    private static Blob createMinimalPdf() {
        String pdf = '%PDF-1.4\n';
        List<Integer> offsets = new List<Integer>();

        offsets.add(pdf.length());
        pdf += '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';

        offsets.add(pdf.length());
        pdf += '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n';

        offsets.add(pdf.length());
        pdf += '3 0 obj\n<< /Type /Page /Parent 2 0 R '
             + '/MediaBox [0 0 612 792] /Contents 4 0 R '
             + '/Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n';

        String streamData = 'BT /F1 12 Tf 72 720 Td (Test) Tj ET';
        offsets.add(pdf.length());
        pdf += '4 0 obj\n<< /Length ' + streamData.length() + ' >>\nstream\n'
             + streamData + '\nendstream\nendobj\n';

        offsets.add(pdf.length());
        pdf += '5 0 obj\n<< /Type /Font /Subtype /Type1 '
             + '/BaseFont /Helvetica >>\nendobj\n';

        Integer xrefOffset = pdf.length();
        pdf += 'xref\n0 6\n';
        pdf += '0000000000 65535 f \n';
        for (Integer o : offsets) {
            pdf += String.valueOf(o).leftPad(10, '0') + ' 00000 n \n';
        }

        pdf += 'trailer\n<< /Size 6 /Root 1 0 R >>\n';
        pdf += 'startxref\n' + xrefOffset + '\n%%EOF';

        return Blob.valueOf(pdf);
    }

    // ================================================================
    // RC4 — Known test vector
    // ================================================================
    @IsTest
    static void testRC4KnownVector() {
        List<Integer> key = new List<Integer>{0x4B, 0x65, 0x79};
        List<Integer> pt  = new List<Integer>{
            0x50, 0x6C, 0x61, 0x69, 0x6E, 0x74, 0x65, 0x78, 0x74
        };
        List<Integer> enc = DocGenRC4.encrypt(key, pt);
        System.assertEquals(9, enc.size());
        System.assertEquals(0xBB, enc[0]);
        System.assertEquals(0xF3, enc[1]);
    }

    @IsTest
    static void testRC4SymmetricRoundTrip() {
        List<Integer> key  = new List<Integer>{0x01, 0x02, 0x03};
        List<Integer> data = new List<Integer>{0xAA, 0xBB, 0xCC, 0xDD};
        List<Integer> enc  = DocGenRC4.encrypt(key, data);
        List<Integer> dec  = DocGenRC4.encrypt(key, enc);
        System.assertEquals(data, dec);
    }

    // ================================================================
    // Password padding
    // ================================================================
    @IsTest
    static void testPadPasswordNormal() {
        List<Integer> p = DocGenPdfEncryptor.padPassword('test');
        System.assertEquals(32, p.size());
        System.assertEquals(0x74, p[0]); // 't'
        System.assertEquals(DocGenPdfEncryptor.PASSWORD_PADDING[0], p[4]);
    }

    @IsTest
    static void testPadPasswordEmpty() {
        List<Integer> p = DocGenPdfEncryptor.padPassword('');
        System.assertEquals(32, p.size());
        System.assertEquals(DocGenPdfEncryptor.PASSWORD_PADDING[0], p[0]);
    }

    @IsTest
    static void testPadPasswordNull() {
        List<Integer> p = DocGenPdfEncryptor.padPassword(null);
        System.assertEquals(32, p.size());
        System.assertEquals(DocGenPdfEncryptor.PASSWORD_PADDING[0], p[0]);
    }

    @IsTest
    static void testPadPasswordLong() {
        String longPw = 'abcdefghijklmnopqrstuvwxyz1234567890';
        List<Integer> p = DocGenPdfEncryptor.padPassword(longPw);
        System.assertEquals(32, p.size());
        System.assertEquals(0x61, p[0]); // 'a'
        System.assertEquals(0x7A, p[25]); // 'z'
    }

    // ================================================================
    // Encryption context
    // ================================================================
    @IsTest
    static void testBuildContext() {
        DocGenPdfEncryptor.PermissionSet perms = new DocGenPdfEncryptor.PermissionSet();
        perms.allowPrint = true;

        Test.startTest();
        DocGenPdfEncryptor.EncryptionContext ctx =
            DocGenPdfEncryptor.buildContext('user', 'owner', perms);
        Test.stopTest();

        System.assertEquals(16, ctx.encryptionKey.size(), 'Key must be 128-bit');
        System.assertEquals(32, ctx.ownerHash.size(), 'O must be 32 bytes');
        System.assertEquals(32, ctx.userHash.size(), 'U must be 32 bytes');
        System.assertEquals(16, ctx.fileId.size(), 'File ID must be 16 bytes');
    }

    @IsTest
    static void testBuildContextNoOwnerThrows() {
        Boolean caught = false;
        try {
            DocGenPdfEncryptor.buildContext('user', '', new DocGenPdfEncryptor.PermissionSet());
        } catch (DocGenPdfEncryptor.DocGenEncryptionException e) {
            caught = true;
        }
        System.assert(caught);
    }

    @IsTest
    static void testDifferentPasswordsDifferentKeys() {
        DocGenPdfEncryptor.PermissionSet p = new DocGenPdfEncryptor.PermissionSet();
        DocGenPdfEncryptor.EncryptionContext c1 =
            DocGenPdfEncryptor.buildContext('u1', 'o1', p);
        DocGenPdfEncryptor.EncryptionContext c2 =
            DocGenPdfEncryptor.buildContext('u2', 'o2', p);
        System.assertNotEquals(
            DocGenPdfEncryptor.listToHex(c1.encryptionKey),
            DocGenPdfEncryptor.listToHex(c2.encryptionKey)
        );
    }

    @IsTest
    static void testOwnerHashDeterministic() {
        List<Integer> oPw = DocGenPdfEncryptor.padPassword('owner');
        List<Integer> uPw = DocGenPdfEncryptor.padPassword('user');
        List<Integer> h1  = DocGenPdfEncryptor.computeOwnerHashR3(oPw, uPw);
        List<Integer> h2  = DocGenPdfEncryptor.computeOwnerHashR3(oPw, uPw);
        System.assertEquals(
            DocGenPdfEncryptor.listToHex(h1),
            DocGenPdfEncryptor.listToHex(h2)
        );
    }

    // ================================================================
    // Per-object key uniqueness
    // ================================================================
    @IsTest
    static void testPerObjectKeyDiffers() {
        DocGenPdfEncryptor.EncryptionContext ctx =
            DocGenPdfEncryptor.buildContext('u', 'o', new DocGenPdfEncryptor.PermissionSet());
        Blob k1 = DocGenPdfEncryptor.deriveObjectKey(ctx.encryptionKey, 1, 0);
        Blob k2 = DocGenPdfEncryptor.deriveObjectKey(ctx.encryptionKey, 2, 0);
        System.assertNotEquals(
            EncodingUtil.convertToHex(k1),
            EncodingUtil.convertToHex(k2)
        );
    }

    // ================================================================
    // AES encryption
    // ================================================================
    @IsTest
    static void testAesEncryptionOutput() {
        DocGenPdfEncryptor.EncryptionContext ctx =
            DocGenPdfEncryptor.buildContext('u', 'o', new DocGenPdfEncryptor.PermissionSet());
        Blob pt = Blob.valueOf('Hello encrypted world');

        Blob enc = DocGenPdfEncryptor.encryptObjectData(ctx, pt, 4, 0);

        System.assertNotEquals(null, enc);
        System.assert(enc.size() >= 32, 'Must include IV (16) + at least one block (16)');
    }

    @IsTest
    static void testAesEncryptionNonDeterministic() {
        // Different IVs should produce different ciphertext
        DocGenPdfEncryptor.EncryptionContext ctx =
            DocGenPdfEncryptor.buildContext('u', 'o', new DocGenPdfEncryptor.PermissionSet());
        Blob pt = Blob.valueOf('Same plaintext');
        Blob enc1 = DocGenPdfEncryptor.encryptObjectData(ctx, pt, 4, 0);
        Blob enc2 = DocGenPdfEncryptor.encryptObjectData(ctx, pt, 4, 0);
        System.assertNotEquals(
            EncodingUtil.convertToHex(enc1),
            EncodingUtil.convertToHex(enc2),
            'Random IVs must produce different output'
        );
    }

    // ================================================================
    // Permission flags
    // ================================================================
    @IsTest
    static void testPermissionsDenyAll() {
        DocGenPdfEncryptor.PermissionSet p = new DocGenPdfEncryptor.PermissionSet();
        Integer v = p.toInteger();
        System.assertEquals(0, v & DocGenPdfEncryptor.PERM_PRINT);
        System.assertEquals(0, v & DocGenPdfEncryptor.PERM_MODIFY);
        System.assertEquals(0, v & DocGenPdfEncryptor.PERM_COPY);
    }

    @IsTest
    static void testPermissionsAllowAll() {
        DocGenPdfEncryptor.PermissionSet p = new DocGenPdfEncryptor.PermissionSet();
        p.allowPrint = true;
        p.allowModify = true;
        p.allowCopy = true;
        p.allowAnnotate = true;
        p.allowFillForms = true;
        p.allowAssembly = true;
        Integer v = p.toInteger();
        System.assertNotEquals(0, v & DocGenPdfEncryptor.PERM_PRINT);
        System.assertNotEquals(0, v & DocGenPdfEncryptor.PERM_MODIFY);
        System.assertNotEquals(0, v & DocGenPdfEncryptor.PERM_COPY);
        System.assertNotEquals(0, v & DocGenPdfEncryptor.PERM_ANNOT);
        System.assertNotEquals(0, v & DocGenPdfEncryptor.PERM_FILL_FORMS);
        System.assertNotEquals(0, v & DocGenPdfEncryptor.PERM_ASSEMBLE);
    }

    // ================================================================
    // PDF Rewriter — full encryption cycle
    // ================================================================
    @IsTest
    static void testEncryptPdfBothPasswords() {
        Blob source = createMinimalPdf();
        DocGenPdfEncryptor.PermissionSet perms = new DocGenPdfEncryptor.PermissionSet();
        perms.allowPrint = true;

        Test.startTest();
        Blob result = DocGenPdfBuilder.encryptPdf(source, 'viewpw', 'editpw', perms);
        Test.stopTest();

        String resultStr = result.toString();
        System.assert(resultStr.contains('%PDF-'), 'Must have PDF header');
        System.assert(resultStr.contains('/AESV2'), 'Must use AESV2 crypt filter');
        System.assert(resultStr.contains('/R 4'), 'Must be Revision 4');
        System.assert(resultStr.contains('%%EOF'), 'Must have EOF marker');
        System.assert(result.size() > source.size(), 'Encrypted must be larger');
    }

    @IsTest
    static void testEncryptPdfOwnerOnly() {
        Blob source = createMinimalPdf();
        DocGenPdfEncryptor.PermissionSet perms = new DocGenPdfEncryptor.PermissionSet();

        Blob result = DocGenPdfBuilder.encryptPdf(source, null, 'editpw', perms);

        String resultStr = result.toString();
        System.assert(resultStr.contains('/AESV2'));
        System.assert(result.size() > source.size());
    }

    @IsTest
    static void testEncryptPdfUserOnly() {
        Blob source = createMinimalPdf();
        DocGenPdfEncryptor.PermissionSet perms = new DocGenPdfEncryptor.PermissionSet();

        Blob result = DocGenPdfBuilder.encryptPdf(source, 'viewpw', null, perms);

        String resultStr = result.toString();
        System.assert(resultStr.contains('/AESV2'));
    }

    @IsTest
    static void testEncryptPdfNoPasswordsReturnsOriginal() {
        Blob source = createMinimalPdf();
        DocGenPdfEncryptor.PermissionSet perms = new DocGenPdfEncryptor.PermissionSet();

        Blob result = DocGenPdfBuilder.encryptPdf(source, null, null, perms);

        System.assertEquals(
            EncodingUtil.convertToHex(source),
            EncodingUtil.convertToHex(result),
            'No passwords = no encryption, return original'
        );
    }

    @IsTest
    static void testEncryptPdfEmptyPasswordsReturnsOriginal() {
        Blob source = createMinimalPdf();
        DocGenPdfEncryptor.PermissionSet perms = new DocGenPdfEncryptor.PermissionSet();

        Blob result = DocGenPdfBuilder.encryptPdf(source, '', '', perms);

        System.assertEquals(
            EncodingUtil.convertToHex(source),
            EncodingUtil.convertToHex(result)
        );
    }

    // ================================================================
    // PDF Rewriter — validation
    // ================================================================
    @IsTest
    static void testRejectsNonPdf() {
        Boolean caught = false;
        try {
            DocGenPdfBuilder.encryptPdf(
                Blob.valueOf('not a pdf'), 'u', 'o',
                new DocGenPdfEncryptor.PermissionSet()
            );
        } catch (DocGenPdfEncryptor.DocGenEncryptionException e) {
            caught = true;
            System.assert(e.getMessage().contains('header'));
        }
        System.assert(caught);
    }

    @IsTest
    static void testRejectsAlreadyEncrypted() {
        // Create a minimal PDF that contains /Encrypt in its trailer
        String pdf = '%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n'
            + 'xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n'
            + 'trailer\n<< /Size 2 /Root 1 0 R /Encrypt 3 0 R >>\n'
            + 'startxref\n52\n%%EOF';

        Boolean caught = false;
        try {
            DocGenPdfBuilder.encryptPdf(
                Blob.valueOf(pdf), 'u', 'o',
                new DocGenPdfEncryptor.PermissionSet()
            );
        } catch (DocGenPdfEncryptor.DocGenEncryptionException e) {
            caught = true;
            System.assert(e.getMessage().contains('already encrypted'));
        }
        System.assert(caught);
    }

    // ================================================================
    // PDF Structure parsing
    // ================================================================
    @IsTest
    static void testParsePdfStructure() {
        Blob source = createMinimalPdf();
        String hex = EncodingUtil.convertToHex(source);

        DocGenPdfBuilder.PdfStructure s = DocGenPdfBuilder.parsePdfStructure(hex);

        System.assertEquals(5, s.objects.size(), 'Should find 5 objects');
        System.assertEquals(5, s.maxObjectNumber);
        System.assertNotEquals(-1, s.xrefHexPos);
        System.assertNotEquals(-1, s.trailerHexPos);
        System.assertEquals('1 0 R', s.rootRef);

        // Object 4 should have a stream
        Boolean foundStream = false;
        for (DocGenPdfBuilder.PdfObject obj : s.objects) {
            if (obj.objectNumber == 4) {
                System.assert(obj.hasStream, 'Object 4 must have a stream');
                System.assertNotEquals(null, obj.streamDataHexStart);
                System.assertNotEquals(null, obj.streamDataHexEnd);
                foundStream = true;
            }
        }
        System.assert(foundStream, 'Must find object 4');
    }

    // ================================================================
    // Hex utilities
    // ================================================================
    @IsTest
    static void testHexAsciiRoundTrip() {
        String original = 'Hello World 123';
        String hex = DocGenPdfBuilder.asciiToHex(original);
        String restored = DocGenPdfBuilder.hexToAscii(hex);
        System.assertEquals(original, restored);
    }

    @IsTest
    static void testBlobListRoundTrip() {
        List<Integer> original = new List<Integer>{0, 127, 255, 16, 32};
        Blob b = DocGenPdfEncryptor.listToBlob(original);
        List<Integer> restored = DocGenPdfEncryptor.blobToList(b, original.size());
        for (Integer i = 0; i < original.size(); i++) {
            System.assertEquals(original[i], restored[i], 'Byte ' + i + ' mismatch');
        }
    }

    // ================================================================
    // Governor limit safety
    // ================================================================
    @IsTest
    static void testGovernorLimitSafety() {
        Blob source = createMinimalPdf();
        DocGenPdfEncryptor.PermissionSet perms = new DocGenPdfEncryptor.PermissionSet();

        Test.startTest();
        Integer cpuBefore = Limits.getCpuTime();
        Integer heapBefore = Limits.getHeapSize();

        Blob result = DocGenPdfBuilder.encryptPdf(source, 'user', 'owner', perms);

        Integer cpuUsed = Limits.getCpuTime() - cpuBefore;
        Integer heapUsed = Limits.getHeapSize() - heapBefore;
        Test.stopTest();

        System.assert(cpuUsed < 5000,
            'CPU (' + cpuUsed + 'ms) must stay under 50% of sync limit');
        System.assert(heapUsed < 3000000,
            'Heap (' + heapUsed + ') must stay under 50% of sync limit');
    }

    // ================================================================
    // Invocable — validation
    // ================================================================
    @IsTest
    static void testInvocableNoSource() {
        DocGenEncryptPdfAction.Request req = new DocGenEncryptPdfAction.Request();
        req.recordId = UserInfo.getUserId();
        req.fileName = 'Test';

        List<DocGenEncryptPdfAction.Response> results =
            DocGenEncryptPdfAction.encryptPdfs(
                new List<DocGenEncryptPdfAction.Request>{req}
            );

        System.assertEquals('Error', results[0].status);
        System.assert(results[0].errorMessage.contains('Source Content'));
    }

    @IsTest
    static void testInvocableNoFileName() {
        DocGenEncryptPdfAction.Request req = new DocGenEncryptPdfAction.Request();
        req.recordId = UserInfo.getUserId();
        req.htmlContent = '<html><body>Test</body></html>';
        req.fileName = '';

        List<DocGenEncryptPdfAction.Response> results =
            DocGenEncryptPdfAction.encryptPdfs(
                new List<DocGenEncryptPdfAction.Request>{req}
            );

        System.assertEquals('Error', results[0].status);
    }

    // ================================================================
    // Queueable end-to-end with existing ContentVersion
    // ================================================================
    @IsTest
    static void testQueueableFromContentVersion() {
        Account testAcc = new Account(Name = 'Encryption Test');
        insert testAcc;

        // Create source PDF
        ContentVersion sourceCv = new ContentVersion();
        sourceCv.Title = 'Source';
        sourceCv.PathOnClient = 'Source.pdf';
        sourceCv.VersionData = createMinimalPdf();
        insert sourceCv;
        sourceCv = [SELECT Id FROM ContentVersion WHERE Id = :sourceCv.Id];

        DocGenEncryptPdfAction.Request req = new DocGenEncryptPdfAction.Request();
        req.recordId = testAcc.Id;
        req.sourceContentVersionId = sourceCv.Id;
        req.fileName = 'Encrypted';
        req.ownerPassword = 'editpw';
        req.allowPrint = true;
        req.allowCopy = false;

        Test.startTest();
        List<DocGenEncryptPdfAction.Response> results =
            DocGenEncryptPdfAction.encryptPdfs(
                new List<DocGenEncryptPdfAction.Request>{req}
            );
        Test.stopTest();

        System.assert(results[0].status.startsWith('Queued'));

        List<ContentDocumentLink> links = [
            SELECT ContentDocumentId FROM ContentDocumentLink
            WHERE LinkedEntityId = :testAcc.Id
        ];
        System.assertEquals(1, links.size(), 'Encrypted PDF must be attached');
    }

    // ================================================================
    // Queueable with HTML content
    // ================================================================
    @IsTest
    static void testQueueableFromHtml() {
        Account testAcc = new Account(Name = 'HTML Test');
        insert testAcc;

        DocGenEncryptPdfAction.Request req = new DocGenEncryptPdfAction.Request();
        req.recordId = testAcc.Id;
        req.htmlContent = '<html><body><h1>Test Document</h1><p>Content here.</p></body></html>';
        req.fileName = 'HtmlEncrypted';
        req.userPassword = 'viewpw';
        req.ownerPassword = 'editpw';
        req.allowPrint = false;

        Test.startTest();
        DocGenEncryptPdfAction.encryptPdfs(
            new List<DocGenEncryptPdfAction.Request>{req}
        );
        Test.stopTest();

        List<ContentDocumentLink> links = [
            SELECT ContentDocumentId FROM ContentDocumentLink
            WHERE LinkedEntityId = :testAcc.Id
        ];
        System.assertEquals(1, links.size());
    }

    // ================================================================
    // Bulk — multiple requests
    // ================================================================
    @IsTest
    static void testBulkEncryption() {
        Account a1 = new Account(Name = 'Bulk1');
        Account a2 = new Account(Name = 'Bulk2');
        insert new List<Account>{a1, a2};

        Blob sourcePdf = createMinimalPdf();
        ContentVersion cv1 = new ContentVersion(
            Title = 'S1', PathOnClient = 'S1.pdf', VersionData = sourcePdf
        );
        ContentVersion cv2 = new ContentVersion(
            Title = 'S2', PathOnClient = 'S2.pdf', VersionData = sourcePdf
        );
        insert new List<ContentVersion>{cv1, cv2};
        cv1 = [SELECT Id FROM ContentVersion WHERE Id = :cv1.Id];
        cv2 = [SELECT Id FROM ContentVersion WHERE Id = :cv2.Id];

        DocGenEncryptPdfAction.Request r1 = new DocGenEncryptPdfAction.Request();
        r1.recordId = a1.Id;
        r1.sourceContentVersionId = cv1.Id;
        r1.fileName = 'Enc1';
        r1.ownerPassword = 'edit1';

        DocGenEncryptPdfAction.Request r2 = new DocGenEncryptPdfAction.Request();
        r2.recordId = a2.Id;
        r2.sourceContentVersionId = cv2.Id;
        r2.fileName = 'Enc2';
        r2.userPassword = 'view2';
        r2.ownerPassword = 'edit2';

        Test.startTest();
        List<DocGenEncryptPdfAction.Response> results =
            DocGenEncryptPdfAction.encryptPdfs(
                new List<DocGenEncryptPdfAction.Request>{r1, r2}
            );
        Test.stopTest();

        for (DocGenEncryptPdfAction.Response resp : results) {
            System.assert(resp.status.startsWith('Queued'), 'Status: ' + resp.status);
        }
    }

    // ================================================================
    // No-password passthrough
    // ================================================================
    @IsTest
    static void testQueueableNoPasswordsNoEncryption() {
        Account testAcc = new Account(Name = 'NoPass Test');
        insert testAcc;

        ContentVersion sourceCv = new ContentVersion(
            Title = 'Source', PathOnClient = 'Source.pdf',
            VersionData = createMinimalPdf()
        );
        insert sourceCv;
        sourceCv = [SELECT Id FROM ContentVersion WHERE Id = :sourceCv.Id];

        DocGenEncryptPdfAction.Request req = new DocGenEncryptPdfAction.Request();
        req.recordId = testAcc.Id;
        req.sourceContentVersionId = sourceCv.Id;
        req.fileName = 'Unencrypted';
        // No passwords set

        Test.startTest();
        DocGenEncryptPdfAction.encryptPdfs(
            new List<DocGenEncryptPdfAction.Request>{req}
        );
        Test.stopTest();

        List<ContentDocumentLink> links = [
            SELECT ContentDocumentId FROM ContentDocumentLink
            WHERE LinkedEntityId = :testAcc.Id
        ];
        System.assertEquals(1, links.size());
    }

    // ================================================================
    // Schedulable
    // ================================================================
    @IsTest
    static void testSchedulableFallback() {
        Account testAcc = new Account(Name = 'Schedule Test');
        insert testAcc;

        ContentVersion sourceCv = new ContentVersion(
            Title = 'S', PathOnClient = 'S.pdf',
            VersionData = createMinimalPdf()
        );
        insert sourceCv;
        sourceCv = [SELECT Id FROM ContentVersion WHERE Id = :sourceCv.Id];

        DocGenEncryptPdfAction.Request req = new DocGenEncryptPdfAction.Request();
        req.recordId = testAcc.Id;
        req.sourceContentVersionId = sourceCv.Id;
        req.fileName = 'ScheduledEnc';
        req.ownerPassword = 'edit';

        List<DocGenEncryptPdfAction.Request> requests =
            new List<DocGenEncryptPdfAction.Request>{req};

        Test.startTest();
        DocGenEncryptionSchedulable sched = new DocGenEncryptionSchedulable(requests);
        sched.execute(null);
        Test.stopTest();

        List<ContentDocumentLink> links = [
            SELECT ContentDocumentId FROM ContentDocumentLink
            WHERE LinkedEntityId = :testAcc.Id
        ];
        System.assertEquals(1, links.size());
    }
}
