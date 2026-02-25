/**
 * @description Queueable worker with chain-first architecture.
 *
 *              CRITICAL DESIGN: System.enqueueJob() for the NEXT request
 *              is called BEFORE the ContentVersion DML insert. This prevents
 *              triggers on ContentVersion from consuming our one permitted
 *              enqueue slot and breaking the chain.
 *
 *              Each transaction gets fresh async governor limits:
 *              12 MB heap, 60,000 ms CPU.
 *
 *              If chaining fails (slot already consumed), falls back to
 *              DocGenEncryptionSchedulable which runs in a fresh sync context.
 *
 * @group DocGen PDF Security
 */
public with sharing class DocGenEncryptionQueueable implements Queueable {

    private DocGenEncryptPdfAction.Request currentRequest;
    private List<DocGenEncryptPdfAction.Request> remainingRequests;

    public DocGenEncryptionQueueable(
        DocGenEncryptPdfAction.Request current,
        List<DocGenEncryptPdfAction.Request> remaining
    ) {
        this.currentRequest = current;
        this.remainingRequests = remaining;
    }

    public void execute(QueueableContext qc) {
        // STEP 1: Chain FIRST — before any DML that could trigger
        // automations consuming our one enqueue slot
        Boolean chained = chainNext();

        // STEP 2: Process current request
        try {
            processRequest(currentRequest);
        } catch (Exception e) {
            System.debug(LoggingLevel.ERROR,
                'DocGen encryption failed for ' + currentRequest.recordId +
                ': ' + e.getMessage() + '\n' + e.getStackTraceString()
            );
        }

        // STEP 3: Clear passwords from heap
        currentRequest.userPassword = null;
        currentRequest.ownerPassword = null;
        currentRequest = null;

        // STEP 4: If chain failed, fall back to schedulable
        if (!chained && remainingRequests != null && !remainingRequests.isEmpty()) {
            fallbackSchedule();
        }
    }

    private Boolean chainNext() {
        if (remainingRequests == null || remainingRequests.isEmpty()) {
            return true; // nothing to chain
        }
        try {
            if (Limits.getQueueableJobs() < Limits.getLimitQueueableJobs()) {
                DocGenEncryptPdfAction.Request next = remainingRequests.remove(0);
                List<DocGenEncryptPdfAction.Request> rest =
                    remainingRequests.isEmpty() ? null : remainingRequests;
                System.enqueueJob(new DocGenEncryptionQueueable(next, rest));
                return true;
            }
            return false;
        } catch (Exception e) {
            System.debug(LoggingLevel.WARN,
                'DocGen chain failed: ' + e.getMessage());
            return false;
        }
    }

    private void fallbackSchedule() {
        try {
            Datetime runAt = Datetime.now().addMinutes(1);
            String cron = runAt.second() + ' ' + runAt.minute() + ' ' +
                runAt.hour() + ' ' + runAt.day() + ' ' + runAt.month() +
                ' ? ' + runAt.year();
            System.schedule(
                'DocGen Encrypt Overflow ' + Datetime.now().getTime(),
                cron,
                new DocGenEncryptionSchedulable(remainingRequests)
            );
        } catch (Exception e) {
            System.debug(LoggingLevel.ERROR,
                'DocGen fallback schedule failed: ' + e.getMessage() +
                '. ' + remainingRequests.size() + ' requests not processed.');
        }
    }

    private void processRequest(DocGenEncryptPdfAction.Request req) {
        DocGenPdfEncryptor.PermissionSet perms = new DocGenPdfEncryptor.PermissionSet();
        perms.allowPrint    = req.allowPrint == true;
        perms.allowModify   = req.allowModify == true;
        perms.allowCopy     = req.allowCopy == true;
        perms.allowAnnotate = req.allowAnnotate == true;

        // Obtain source PDF
        Blob sourcePdf;
        if (req.sourceContentVersionId != null) {
            ContentVersion cv = [
                SELECT VersionData FROM ContentVersion
                WHERE Id = :req.sourceContentVersionId
                LIMIT 1
            ];
            sourcePdf = cv.VersionData;
        } else {
            sourcePdf = Blob.toPdf(req.htmlContent);
            req.htmlContent = null;
        }

        // Validate size — leave room for hex expansion + encryption overhead
        Integer maxSafe = (Limits.getLimitHeapSize() - Limits.getHeapSize()) / 4;
        if (sourcePdf.size() > maxSafe) {
            throw new DocGenPdfEncryptor.DocGenEncryptionException(
                'PDF size (' + sourcePdf.size() + ' bytes) exceeds safe limit (' +
                maxSafe + ' bytes). Reduce content or simplify document.'
            );
        }

        // Encrypt
        Blob encryptedPdf = DocGenPdfBuilder.encryptPdf(
            sourcePdf,
            req.userPassword,
            req.ownerPassword,
            perms
        );

        sourcePdf = null;
        req.userPassword = null;
        req.ownerPassword = null;

        // Save
        ContentVersion newCv = new ContentVersion();
        newCv.Title = req.fileName;
        newCv.PathOnClient = req.fileName + '.pdf';
        newCv.VersionData = encryptedPdf;
        newCv.IsMajorVersion = true;
        newCv.FirstPublishLocationId = req.recordId;
        insert newCv;
    }
}
