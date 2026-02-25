/**
 * @description One-time Schedulable fallback for when System.enqueueJob()
 *              cannot be called (all async slots consumed in the current
 *              transaction).
 *
 *              Schedules itself ~1 minute in the future. At execution,
 *              it runs in a fresh synchronous context with 50 available
 *              enqueue slots and chains remaining work as a Queueable.
 *
 * @group DocGen PDF Security
 */
public with sharing class DocGenEncryptionSchedulable implements Schedulable {

    private List<DocGenEncryptPdfAction.Request> requests;

    public DocGenEncryptionSchedulable(List<DocGenEncryptPdfAction.Request> requests) {
        this.requests = requests;
    }

    public void execute(SchedulableContext sc) {
        if (requests != null && !requests.isEmpty()) {
            DocGenEncryptPdfAction.Request first = requests.remove(0);
            List<DocGenEncryptPdfAction.Request> rest =
                requests.isEmpty() ? null : requests;
            System.enqueueJob(new DocGenEncryptionQueueable(first, rest));
        }

        // Clean up one-time scheduled job
        try {
            System.abortJob(sc.getTriggerId());
        } catch (Exception e) {
            // Already cleaned up — safe to ignore
        }
    }
}
