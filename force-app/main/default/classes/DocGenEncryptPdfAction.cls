/**
 * @description Invocable Action for PDF encryption. Designed for Screen Flows,
 *              Record-Triggered Flows, and direct Apex invocation.
 *
 *              View and Edit passwords are independent and optional.
 *              If neither is set, the PDF is returned unchanged.
 *
 *              Detects execution context (@future, Queueable, Batch, sync)
 *              and adapts its async enqueue strategy to avoid governor
 *              limit exceptions from nested async calls.
 *
 * @group DocGen PDF Security
 */
public with sharing class DocGenEncryptPdfAction {

    // ================================================================
    // Request — all configuration via @InvocableVariable
    // ================================================================
    public class Request {
        @InvocableVariable(
            label='Record ID'
            description='Record to attach the encrypted PDF to'
            required=true
        )
        public Id recordId;

        @InvocableVariable(
            label='Source Content Version ID'
            description='Existing ContentVersion to encrypt. Takes priority over HTML Content.'
        )
        public Id sourceContentVersionId;

        @InvocableVariable(
            label='HTML Content'
            description='HTML for Blob.toPdf(). Used only when Source Content Version ID is blank.'
        )
        public String htmlContent;

        @InvocableVariable(
            label='Output File Name'
            description='File name without .pdf extension'
            required=true
        )
        public String fileName;

        @InvocableVariable(
            label='View Password'
            description='Password to open the PDF. Blank = opens without prompt.'
        )
        public String userPassword;

        @InvocableVariable(
            label='Edit Password'
            description='Password for full access. Blank = no separate edit restriction (or auto-derived if View Password is set).'
        )
        public String ownerPassword;

        @InvocableVariable(label='Allow Printing' description='Default: false')
        public Boolean allowPrint;

        @InvocableVariable(label='Allow Modification' description='Default: false')
        public Boolean allowModify;

        @InvocableVariable(label='Allow Copying' description='Default: false')
        public Boolean allowCopy;

        @InvocableVariable(label='Allow Annotating' description='Default: false')
        public Boolean allowAnnotate;
    }

    // ================================================================
    // Response — returned to Flow
    // ================================================================
    public class Response {
        @InvocableVariable(label='Job ID')
        public Id jobId;

        @InvocableVariable(label='Status')
        public String status;

        @InvocableVariable(label='Error Message')
        public String errorMessage;
    }

    // ================================================================
    // Main invocable method
    // ================================================================
    @InvocableMethod(
        label='Encrypt PDF with Password Protection'
        description='Encrypts a PDF with optional independent view/edit passwords and permission controls. No prompt if password not set.'
        category='DocGen'
    )
    public static List<Response> encryptPdfs(List<Request> requests) {
        List<Response> responses = new List<Response>();

        // Validate
        List<Request> validRequests = new List<Request>();
        for (Request req : requests) {
            Response resp = validateRequest(req);
            if (resp != null) {
                responses.add(resp);
            } else {
                validRequests.add(req);
                responses.add(null); // placeholder
            }
        }

        if (validRequests.isEmpty()) {
            return responses;
        }

        // Context-aware enqueue
        Boolean isAsync =
            System.isQueueable() || System.isFuture() || System.isBatch();
        Integer slotsUsed     = Limits.getQueueableJobs();
        Integer slotsLimit    = Limits.getLimitQueueableJobs();
        Integer slotsLeft     = slotsLimit - slotsUsed;

        if (slotsLeft <= 0) {
            return scheduleFallback(validRequests, responses, requests);
        }

        if (isAsync) {
            return enqueueBundled(validRequests, responses, requests);
        }

        return enqueueSyncStrategy(validRequests, responses, requests);
    }

    // ================================================================
    // Sync context: up to 50 individual enqueues, overflow chains
    // ================================================================
    private static List<Response> enqueueSyncStrategy(
        List<Request> valid, List<Response> responses, List<Request> all
    ) {
        Integer slotsLeft = Limits.getLimitQueueableJobs() - Limits.getQueueableJobs();
        try {
            if (valid.size() <= slotsLeft) {
                Integer vIdx = 0;
                for (Integer i = 0; i < all.size(); i++) {
                    if (responses[i] == null && vIdx < valid.size()) {
                        Id jId = System.enqueueJob(
                            new DocGenEncryptionQueueable(valid[vIdx], null)
                        );
                        responses.set(i, makeResponse(jId, 'Queued'));
                        vIdx++;
                    }
                }
            } else {
                // Bundle into one chained Queueable
                return enqueueBundled(valid, responses, all);
            }
        } catch (Exception e) {
            fillErrors(responses, all, e.getMessage());
        }
        return responses;
    }

    // ================================================================
    // Async/bundled: single enqueue with chain
    // ================================================================
    private static List<Response> enqueueBundled(
        List<Request> valid, List<Response> responses, List<Request> all
    ) {
        try {
            Request first = valid[0];
            List<Request> rest = valid.size() > 1 ? subList(valid, 1) : null;
            Id jId = System.enqueueJob(new DocGenEncryptionQueueable(first, rest));
            fillStatus(responses, all, jId, 'Queued (chained)');
        } catch (Exception e) {
            return scheduleFallback(valid, responses, all);
        }
        return responses;
    }

    // ================================================================
    // Fallback: schedule for ~1 min later in fresh sync context
    // ================================================================
    private static List<Response> scheduleFallback(
        List<Request> valid, List<Response> responses, List<Request> all
    ) {
        try {
            Datetime runAt = Datetime.now().addMinutes(1);
            String cron = runAt.second() + ' ' + runAt.minute() + ' ' +
                runAt.hour() + ' ' + runAt.day() + ' ' + runAt.month() +
                ' ? ' + runAt.year();
            System.schedule(
                'DocGen Encrypt ' + Datetime.now().getTime(),
                cron,
                new DocGenEncryptionSchedulable(valid)
            );
            fillStatus(responses, all, null, 'Scheduled (async overflow)');
        } catch (Exception e) {
            fillErrors(responses, all, 'Cannot enqueue or schedule: ' + e.getMessage());
        }
        return responses;
    }

    // ================================================================
    // Validation
    // ================================================================
    private static Response validateRequest(Request req) {
        if (req.sourceContentVersionId == null && String.isBlank(req.htmlContent)) {
            return makeError('Either Source Content Version ID or HTML Content is required.');
        }
        if (String.isBlank(req.fileName)) {
            return makeError('Output File Name is required.');
        }
        return null; // passwords are optional
    }

    // ================================================================
    // Response helpers
    // ================================================================
    private static Response makeResponse(Id jobId, String status) {
        Response r = new Response();
        r.jobId = jobId;
        r.status = status;
        return r;
    }

    private static Response makeError(String msg) {
        Response r = new Response();
        r.status = 'Error';
        r.errorMessage = msg;
        return r;
    }

    private static void fillStatus(
        List<Response> responses, List<Request> all, Id jobId, String status
    ) {
        for (Integer i = 0; i < all.size(); i++) {
            if (responses[i] == null) {
                responses.set(i, makeResponse(jobId, status));
            }
        }
    }

    private static void fillErrors(
        List<Response> responses, List<Request> all, String msg
    ) {
        for (Integer i = 0; i < all.size(); i++) {
            if (responses[i] == null) {
                responses.set(i, makeError(msg));
            }
        }
    }

    public static List<Request> subList(List<Request> source, Integer fromIndex) {
        List<Request> result = new List<Request>();
        for (Integer i = fromIndex; i < source.size(); i++) {
            result.add(source[i]);
        }
        return result;
    }
}
